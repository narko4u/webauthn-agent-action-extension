#!/usr/bin/env python3
"""Repository validation gate: parses JSON/YAML, checks markdown links and HTML
asset references resolve, compiles Python, then runs an optional .ci/extra.sh."""
import ast, json, os, re, subprocess, sys
from pathlib import Path

SKIP = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
EXT = ("http://", "https://", "//", "mailto:", "#", "tel:", "data:")
errors = []


def walk(suffix):
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for f in files:
            if f.endswith(suffix):
                yield Path(root) / f


def resolves(page, target):
    t = target.split("#")[0].split("?")[0]
    if not t:
        return True
    if t.startswith("/"):
        return Path(t.lstrip("/")).exists()
    return (page.parent / t).exists() or Path(t).exists()


for p in walk(".json"):
    try:
        json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        errors.append(f"JSON invalid: {p}: {e}")

try:
    import yaml
    for p in list(walk(".yml")) + list(walk(".yaml")):
        try:
            yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception as e:
            errors.append(f"YAML invalid: {p}: {str(e)[:80]}")
except ImportError:
    errors.append("PyYAML missing")

for p in walk(".py"):
    try:
        ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
    except SyntaxError as e:
        errors.append(f"Python syntax error: {p}:{e.lineno}: {e.msg}")

LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)\)")
for p in walk(".md"):
    for t in LINK.findall(p.read_text(encoding="utf-8", errors="replace")):
        if not t.startswith(EXT) and not resolves(p, t):
            errors.append(f"Broken link in {p}: {t}")

ATTR = re.compile(r'(?:src|href)="([^"]+)"')
for p in walk(".html"):
    for t in ATTR.findall(p.read_text(encoding="utf-8", errors="replace")):
        if not t.startswith(EXT) and not resolves(p, t):
            errors.append(f"Broken asset in {p}: {t}")

extra = Path(".ci/extra.sh")
if extra.exists() and os.environ.get("SKIP_EXTRA") != "1":
    r = subprocess.run(["bash", str(extra)], capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        errors.append(f".ci/extra.sh failed (exit {r.returncode})")

if errors:
    print(f"FAIL: {len(errors)} problem(s)")
    for e in errors[:50]:
        print("  -", e)
    sys.exit(1)
print("OK: repository validation passed")
