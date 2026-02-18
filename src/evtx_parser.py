import os
from typing import Dict, List, Any, Tuple

from Evtx.Evtx import Evtx  # type: ignore
from xml.etree import ElementTree as ET


Event = Dict[str, Any]


def _parse_event_record_xml(xml_str: str) -> Event:
    """
    Parse an EVTX record (XML) into a simplified key/value dictionary.
    We extract notably:
      - EventID
      - TimeCreated/@SystemTime
      - Computer
      - all Name / text pairs in EventData/Data
    """
    root = ET.fromstring(xml_str)
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    event: Event = {}

    system_node = root.find("e:System", ns)
    if system_node is not None:
        event_id_node = system_node.find("e:EventID", ns)
        if event_id_node is not None and event_id_node.text is not None:
            try:
                event["EventID"] = int(event_id_node.text)
            except ValueError:
                event["EventID"] = event_id_node.text

        time_node = system_node.find("e:TimeCreated", ns)
        if time_node is not None:
            event["TimeCreated"] = time_node.get("SystemTime")

        keywords_node = system_node.find("e:Keywords", ns)
        if keywords_node is not None and keywords_node.text is not None:
            event["Keywords"] = keywords_node.text.strip()

        computer_node = system_node.find("e:Computer", ns)
        if computer_node is not None:
            event["Computer"] = computer_node.text

    event_data_node = root.find("e:EventData", ns)
    if event_data_node is not None:
        for data in event_data_node.findall("e:Data", ns):
            name = data.get("Name")
            if name:
                event[name] = (data.text or "").strip()

    return event


def load_evtx_events(evtx_directory: str, verbose: bool = False) -> Tuple[List[Event], Dict[str, Any]]:
    """
    Load all .evtx files in a directory and return a list of normalized event dictionaries.
    """
    events: List[Event] = []
    files_parsed: List[Dict[str, Any]] = []

    for entry in os.scandir(evtx_directory):
        if not entry.is_file():
            continue
        if not entry.name.lower().endswith(".evtx"):
            continue

        if verbose:
            print(f"\nParsing {entry.path}...")

        before = len(events)
        with Evtx(entry.path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    evt = _parse_event_record_xml(xml_str)
                    events.append(evt)
                except Exception:
                    # We ignore corrupted or unparsable records.
                    continue
        after = len(events)
        count = after - before
        files_parsed.append({"file": entry.path, "events": count})
        if verbose:
            print(f"✔ {count} events parsed")

    stats = {
        "files": files_parsed,
        "total_files": len(files_parsed),
        "total_events": len(events),
    }
    return events, stats

