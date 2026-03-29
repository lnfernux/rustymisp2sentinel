#!/usr/bin/env bash
# Adds any missing keys from local.settings.json.example into local.settings.json
# without overwriting existing values.
python3 - <<'PYEOF'
import json, sys, os

example = "local.settings.json.example"
target  = "local.settings.json"

if not os.path.exists(target):
    print(f"ERROR: {target} not found. Copy from {example} first.")
    sys.exit(1)

with open(example) as f: ex = json.load(f)
with open(target)  as f: tg = json.load(f)

added = []
for k, v in ex["Values"].items():
    if k not in tg["Values"]:
        tg["Values"][k] = v
        added.append(k)

if added:
    with open(target, "w") as f:
        json.dump(tg, f, indent=2)
    print("Added missing keys:", ", ".join(added))
else:
    print("local.settings.json is already up to date.")
PYEOF