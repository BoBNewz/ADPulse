import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

Event = Dict[str, Any]

@dataclass
class DetectionResult:
    attack_name: str
    score: int
    timestamp: Optional[str]
    user: Optional[str]
    ip: Optional[str]
    event_id: int
    details: Optional[str] = None


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    # Ex: 2026-02-18T10:01:23.123Z
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(v)
    except ValueError:
        return None


def _to_int_maybe(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    s = str(value).strip().lower()
    if not s:
        return None
    try:
        if s.startswith("0x"):
            return int(s, 16)
        if s.isdigit():
            return int(s, 10)
        return None
    except ValueError:
        return None


def _values_equal(event_value: Any, rule_value: Any) -> bool:
    """
    Compare tolerantly:
    - YAML can parse 0x17 to int (23)
    - EVTX can contain "0x17", "23", etc.
    """
    if event_value is None:
        return False

    ev_int = _to_int_maybe(event_value)
    rv_int = _to_int_maybe(rule_value)
    if ev_int is not None and rv_int is not None:
        return ev_int == rv_int

    ev_str = str(event_value).strip().lower()
    rv_str = str(rule_value).strip().lower()
    return ev_str == rv_str


def _score_from_table(scoring: Dict[Any, Any], matched: int) -> int:
    """
    scoring: {1: 40, 2: 80, 3: 95} etc.
    - if exact key exists, use it
    - otherwise take the best key <= matched
    """
    if matched <= 0:
        return 0
    normalized: Dict[int, int] = {}
    for k, v in scoring.items():
        try:
            normalized[int(k)] = int(v)
        except Exception:
            continue
    if not normalized:
        return 0
    if matched in normalized:
        return normalized[matched]
    best_key = max((k for k in normalized.keys() if k <= matched), default=None)
    if best_key is None:
        return 0
    return normalized[best_key]


class RuleEngine:
    """
    Generic rule engine driven by YAML.

    Objective: write only rules for new detections.

    Expected schema (simplified):
      - id, name, description
      - event_id: int (target event for display)
      - field_map: {canon: "EVTX field name"} (optional)
      - checks: list of checks:
          - simple equality (default):
              field: ticket_encryption_type
              value: 0x17
            (optional: type: equals)
          - burst:
              type: burst
              count: 10
              seconds: 2
              join_by: [user, ip]
            or in compact form:
              field: event_time
              value: 10
              time: 2
              join_by: [user, ip]
          - audit_success:
              type: audit_success
          - has_previous_event:
              type: has_previous_event
              previous_event_id: 4768
              within_seconds: 2
              join_by: [user, ip]
              previous_checks: [...]
          - preceded_by:
              type: preceded_by
              previous_event_id: 4768
              within_seconds: 2
              join_by: [user, ip]
              previous_checks: [...]
              current_checks: [...]
      - scoring: table {n_matched: percentage}
    """

    AUDIT_SUCCESS_KEYWORD_MASK = 0x8020000000000000

    def __init__(self, rules_directory: str, verbose: bool = False) -> None:
        self.rules_directory = rules_directory
        self.verbose = verbose
        self.rules: List[Dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self) -> None:
        for entry in os.scandir(self.rules_directory):
            if not entry.is_file():
                continue
            if not entry.name.lower().endswith((".yml", ".yaml")):
                continue
            with open(entry.path, "r", encoding="utf-8") as f:
                rule = yaml.safe_load(f)
                if isinstance(rule, dict):
                    self.rules.append(rule)
        if self.verbose:
            print(f"[+] Loaded rules: {len(self.rules)}")

    def run(self, events: List[Event]) -> List[DetectionResult]:
        prepped = self._prepare_events(events)
        detections: List[DetectionResult] = []
        for rule in self.rules:
            detections.extend(self._run_rule(rule, prepped))
        return detections

    def _prepare_events(self, events: List[Event]) -> List[Event]:
        prepped: List[Event] = []
        for idx, e in enumerate(events):
            ev = dict(e)
            ev["_idx"] = idx
            ev["_dt"] = _parse_dt(str(ev.get("TimeCreated", "") or ""))
            prepped.append(ev)
        # Sort by date when possible (None goes to the end)
        prepped.sort(key=lambda x: (x.get("_dt") is None, x.get("_dt") or datetime.max))
        return prepped

    def _field_value(self, e: Event, field: str, field_map: Dict[str, Any]) -> Any:
        actual = field_map.get(field, field)
        if isinstance(actual, list):
            for a in actual:
                if not a:
                    continue
                v = e.get(a)
                if v is None:
                    continue
                if str(v).strip() == "":
                    continue
                return v
            return None
        return e.get(actual)

    def _event_id(self, e: Event) -> int:
        try:
            return int(e.get("EventID", 0))
        except Exception:
            return 0

    def _run_rule(self, rule: Dict[str, Any], events: List[Event]) -> List[DetectionResult]:
        attack_name = str(rule.get("name", rule.get("id", "unknown_attack")))
        event_id = int(rule.get("event_id", 0))
        field_map = rule.get("field_map", {}) or {}
        checks = rule.get("checks", []) or []
        scoring = rule.get("scoring", {}) or {}

        if event_id <= 0:
            return []

        target_events = [e for e in events if self._event_id(e) == event_id]
        if not target_events:
            return []

        # Pre-calculations by rule (burst, index "previous_event")
        burst_cache: Dict[str, set] = {}
        prev_index_cache: Dict[Tuple[int, Tuple[str, ...]], Dict[Tuple[Any, ...], List[Event]]] = {}

        def ensure_burst_event_idxs(spec: Dict[str, Any]) -> set:
            """
            Return a set of event indexes considered in a burst.
            """
            # cache key stable
            key = yaml.safe_dump(spec, sort_keys=True)
            if key in burst_cache:
                return burst_cache[key]

            eid = int(spec.get("event_id", event_id))
            count = int(spec.get("count", spec.get("value", 2)))
            seconds = int(spec.get("seconds", spec.get("time", 1)))
            join_by = spec.get("join_by", ["user", "ip"])
            if not isinstance(join_by, list):
                join_by = ["user", "ip"]

            candidates = [e for e in events if self._event_id(e) == eid and e.get("_dt") is not None]

            # group -> list of (dt, idx)
            from collections import defaultdict

            grouped: Dict[Tuple[Any, ...], List[Event]] = defaultdict(list)
            for e in candidates:
                gk = tuple(self._field_value(e, f, field_map) for f in join_by)
                grouped[gk].append(e)
            for gk in grouped:
                grouped[gk].sort(key=lambda x: x["_dt"])

            burst_idxs: set = set()
            for gk, evs in grouped.items():
                left = 0
                for right in range(len(evs)):
                    while (
                        left < right
                        and (evs[right]["_dt"] - evs[left]["_dt"]).total_seconds() > seconds
                    ):
                        left += 1
                    window_size = right - left + 1
                    if window_size >= count:
                        for i in range(left, right + 1):
                            burst_idxs.add(evs[i]["_idx"])

            burst_cache[key] = burst_idxs
            return burst_idxs

        def ensure_prev_index(prev_event_id: int, join_by: List[str]) -> Dict[Tuple[Any, ...], List[Event]]:
            cache_key = (prev_event_id, tuple(join_by))
            if cache_key in prev_index_cache:
                return prev_index_cache[cache_key]

            prev_events = [e for e in events if self._event_id(e) == prev_event_id and e.get("_dt") is not None]
            from collections import defaultdict

            idx_map: Dict[Tuple[Any, ...], List[Event]] = defaultdict(list)
            for e in prev_events:
                gk = tuple(self._field_value(e, f, field_map) for f in join_by)
                idx_map[gk].append(e)
            for gk in idx_map:
                idx_map[gk].sort(key=lambda x: x["_dt"])

            prev_index_cache[cache_key] = idx_map
            return idx_map

        def eval_simple_check(e: Event, spec: Dict[str, Any]) -> bool:
            ctype = str(spec.get("type") or "").strip().lower()
            field = spec.get("field")
            value = spec.get("value")

            if (field == "event_time") or (ctype == "burst") or ("time" in spec and field is not None):
                burst_idxs = ensure_burst_event_idxs(
                    {
                        "event_id": int(spec.get("event_id", event_id)),
                        "count": int(spec.get("count", spec.get("value", 2))),
                        "seconds": int(spec.get("seconds", spec.get("time", 1))),
                        "join_by": spec.get("join_by", ["user", "ip"]),
                    }
                )
                return e.get("_idx") in burst_idxs

            if ctype in ("not_endswith", "not_ending_with"):
                if not field:
                    return False
                ev = self._field_value(e, str(field), field_map)
                if ev is None:
                    return False
                return not str(ev).endswith(str(value))

            if ctype in ("not_contains", "not_containing"):
                if not field:
                    return False
                ev = self._field_value(e, str(field), field_map)
                if ev is None:
                    return False
                return str(value).lower() not in str(ev).lower()

            if ctype in ("audit_success", "audit_success_keyword"):
                kw = self._field_value(e, "keywords", field_map)
                if kw is None:
                    kw = e.get("Keywords")
                kw_int = _to_int_maybe(kw)
                if kw_int is not None:
                    return (kw_int & self.AUDIT_SUCCESS_KEYWORD_MASK) == self.AUDIT_SUCCESS_KEYWORD_MASK
                # fallback text
                return "audit success" in str(kw or "").lower()

            # default / equals
            if not field:
                return False
            ev = self._field_value(e, str(field), field_map)
            return _values_equal(ev, value)

        def eval_check(e: Event, spec: Dict[str, Any]) -> bool:
            ctype = str(spec.get("type") or "").strip().lower()

            if ctype == "has_previous_event":
                prev_event_id = int(spec.get("previous_event_id"))
                within = int(spec.get("within_seconds", 2))
                join_by = spec.get("join_by", ["user", "ip"])
                if not isinstance(join_by, list):
                    return False
                prev_checks = spec.get("previous_checks", []) or []

                if e.get("_dt") is None:
                    return False
                gk = tuple(self._field_value(e, f, field_map) for f in join_by)
                prev_index = ensure_prev_index(prev_event_id, join_by)
                candidates = prev_index.get(gk, [])
                if not candidates:
                    return False
                # Search for a previous event in the window [dt-within, dt]
                dt = e["_dt"]
                for pe in reversed(candidates):
                    if pe["_dt"] > dt:
                        continue
                    if (dt - pe["_dt"]).total_seconds() > within:
                        break
                    ok = True
                    for pc in prev_checks:
                        if not eval_simple_check(pe, pc):
                            ok = False
                            break
                    if ok:
                        return True
                return False

            if ctype == "preceded_by":
                prev_event_id = int(spec.get("previous_event_id"))
                within = int(spec.get("within_seconds", 2))
                join_by = spec.get("join_by", ["user", "ip"])
                if not isinstance(join_by, list):
                    return False
                prev_checks = spec.get("previous_checks", []) or []
                curr_checks = spec.get("current_checks", []) or []

                if e.get("_dt") is None:
                    return False
                dt = e["_dt"]
                gk = tuple(self._field_value(e, f, field_map) for f in join_by)
                prev_index = ensure_prev_index(prev_event_id, join_by)
                candidates = prev_index.get(gk, [])
                if not candidates:
                    return False

                # current checks on the current event
                for cc in curr_checks:
                    if not eval_simple_check(e, cc):
                        return False

                for pe in reversed(candidates):
                    if pe["_dt"] > dt:
                        continue
                    if (dt - pe["_dt"]).total_seconds() > within:
                        break
                    ok = True
                    for pc in prev_checks:
                        if not eval_simple_check(pe, pc):
                            ok = False
                            break
                    if ok:
                        return True
                return False

            # otherwise simple check
            return eval_simple_check(e, spec)

        detections: List[DetectionResult] = []
        ts_field = str(rule.get("timestamp_field", "timestamp"))
        user_field = str(rule.get("user_field", "user"))
        ip_field = str(rule.get("ip_field", "ip"))
        details_field = str(rule.get("details_field", "service"))

        for e in target_events:
            matched = 0
            for chk in checks:
                if not isinstance(chk, dict):
                    continue
                if eval_check(e, chk):
                    matched += 1

            if matched <= 0:
                continue

            score = _score_from_table(scoring, matched)
            timestamp = self._field_value(e, ts_field, field_map)
            user = self._field_value(e, user_field, field_map)
            ip = self._field_value(e, ip_field, field_map)
            details = self._field_value(e, details_field, field_map)

            detections.append(
                DetectionResult(
                    attack_name=attack_name,
                    score=score,
                    timestamp=str(timestamp) if timestamp is not None else None,
                    user=str(user) if user is not None else None,
                    ip=str(ip) if ip is not None else None,
                    event_id=event_id,
                    details=str(details) if details is not None and str(details).strip() else None,
                )
            )

        if self.verbose:
            print(f"[+] Rule {attack_name}: {len(detections)} detection(s) (EventID {event_id})")

        return detections

