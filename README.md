# AD-EVTX-Analyzer

Analyse des journaux Windows EVTX pour la détection d'attaques Active Directory à l'aide de règles YAML.

## Structure

- `setup.yaml` : configuration haut niveau (chemins, options CLI).
- `main.py` : point d'entrée CLI.
- `rules/` : fichiers de règles au format YAML.
- `evtx/` : répertoire (par défaut) contenant les fichiers `.evtx` à analyser.

## Installation

```bash
pip install -r requirements.txt
```

## Utilisation

```bash
python main.py --evtx-path ./evtx --rules-path ./rules --verbose
```

Options :
- `--evtx-path` : chemin vers le dossier contenant les fichiers `.evtx`.
- `--rules-path` : chemin vers le dossier contenant les règles YAML.
- `--verbose` : affiche des détails supplémentaires sur les détections.

## Exemple de règle : AS-REP Roasting

Un exemple de règle pour détecter une attaque AS-REP Roasting est fourni dans `rules/asrep_roasting.yaml`.  
Elle illustre comment :

- Donner un nom à l'attaque.
- Définir l'`EventID` ciblé (4768).
- Spécifier les critères utilisés par le moteur (type de chiffrement, pré-authentification, rafale d'événements).
- Associer une pondération à 1, 2 ou 3 critères correspondants (40%, 80%, 95%).

