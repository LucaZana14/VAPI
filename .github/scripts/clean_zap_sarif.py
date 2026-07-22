import json
import sys
from urllib.parse import urlparse

# Mappa il 'level' che ZAP assegna in base al risk (High->error, Medium->warning,
# Low/Informational->note) a un punteggio security-severity CVSS-like (0.0-10.0).
# GitHub usa QUESTO campo per i badge Critical/High/Medium/Low nella tab Security,
# non 'level'. Va messo su ogni rule in tool.driver.rules[].properties.
LEVEL_TO_SEVERITY = {
    'error': '9.0',    # Critical/High
    'warning': '6.0',  # Medium
    'note': '3.0',     # Low
}


def clean_uri(v: str) -> str:
    if v.startswith('http'):
        parsed = urlparse(v)
        path = parsed.path.lstrip('/')
        return path if path else 'root'
    return v


def walk_uris(obj):
    """Rende granulari gli URI (evita l'accorpamento su openapi.json) senza toccare level."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == 'uri' and isinstance(v, str):
                obj[k] = clean_uri(v)
            else:
                walk_uris(v)
    elif isinstance(obj, list):
        for item in obj:
            walk_uris(item)


def apply_security_severity(sarif: dict) -> int:
    """Assegna security-severity a ogni rule in base al suo defaultConfiguration.level.
    Ritorna il numero di rule aggiornate."""
    updated = 0
    for run in sarif.get('runs', []):
        rules = run.get('tool', {}).get('driver', {}).get('rules', [])
        for rule in rules:
            level = rule.get('defaultConfiguration', {}).get('level')
            severity = LEVEL_TO_SEVERITY.get(level)
            if severity is None:
                continue
            rule.setdefault('properties', {})['security-severity'] = severity
            updated += 1
    return updated


if __name__ == '__main__':
    try:
        with open('results.json', 'r') as f:
            data = json.load(f)

        walk_uris(data)
        n = apply_security_severity(data)

        with open('results.json', 'w') as f:
            json.dump(data, f)

        print(f'SARIF bonificato: URI resi granulari, security-severity assegnata a {n} rule.')
    except Exception as e:
        print(f'Errore FATALE durante la bonifica: {e}')
        sys.exit(1)