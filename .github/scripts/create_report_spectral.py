import json
import os

# Controllo di sicurezza: se il file è vuoto (es. Spectral è crashato male), creiamo un JSON vuoto
if not os.path.exists("spectral-results.json") or os.path.getsize("spectral-results.json") == 0:
    with open("spectral-results.json", "w") as f:
        f.write("[]")

with open("spectral-results.json", "r") as f:
    issues = json.load(f)
    
# 2. MODIFICA QUI: Python deve leggere il file YAML di VAmPI
with open("openapi.json", "r") as f:
    openapi_lines = f.readlines()

sarif = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "Spectral", "rules": []}},
        "results": []
    }]
}

rules = {}
for issue in issues:
    rule_id = str(issue.get("code", "unknown"))
    if rule_id not in rules:
        rules[rule_id] = {"id": rule_id, "shortDescription": {"text": issue.get("message", "")}}
    
    sev = issue.get("severity", 1)
    level = "error" if sev == 0 else "warning" if sev == 1 else "note"
    
    line_idx = issue.get("range", {}).get("start", {}).get("line", 0)
    
    sarif["runs"][0]["results"].append({
        "ruleId": rule_id,
        "level": level,
        "message": {"text": issue.get("message", "")},
        "locations": [{
            "physicalLocation": {
                # 3. MODIFICA QUI: L'URI che GitHub mostrerà nell'interfaccia
                "artifactLocation": {"uri": "openapi_specs/openapi3.yml"},
                "region": {
                    "startLine": line_idx + 1,
                    "startColumn": issue.get("range", {}).get("start", {}).get("character", 0) + 1
                }
            }
        }]
    })
    
sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())

with open("spectral-results.sarif", "w") as f:
    json.dump(sarif, f, indent=2)