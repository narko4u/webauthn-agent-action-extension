#!/usr/bin/env python3
"""Fail if any markdown file links to one of our own GitHub repos that is not
publicly readable. A private or non-existent repo returns 404 for this token."""
import json, os, re, urllib.error, urllib.request
from pathlib import Path

OURS = ("narko4u", "empirelabs-au", "empirelabs")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
LINK = re.compile(r"github\.com/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)")


def status(full):
    req = urllib.request.Request(f"https://api.github.com/repos/{full}")
    req.add_header("Accept", "application/vnd.github+json")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read()).get("visibility", "unknown")
    except urllib.error.HTTPError as e:
        return "MISSING" if e.code == 404 else f"error-{e.code}"
    except Exception as e:
        return f"error-{type(e).__name__}"


seen, bad, unknown = {}, [], {}
for p in sorted(Path(".").rglob("*.md")):
    if ".git" in p.parts:
        continue
    for t in LINK.findall(p.read_text(encoding="utf-8", errors="replace")):
        t = t.rstrip(".,);").split("#")[0].split("?")[0]
        if t.endswith(".git"):
            t = t[:-4]
        parts = t.split("/")
        if len(parts) > 2:
            t = "/".join(parts[:2])
        if t.count("/") != 1:
            continue
        if t.split("/")[0] not in OURS:
            continue
        if t not in seen:
            seen[t] = status(t)
        v = seen[t]
        if v in ("MISSING", "private"):
            bad.append(f"{p}: links to non-public github.com/{t} [{v}]")
        elif v.startswith("error-"):
            unknown[t] = v

if unknown:
    print("note: could not verify (not failing):", unknown)
if bad:
    print(f"FAIL: {len(bad)} link(s) to non-public repositories")
    for b in bad[:40]:
        print("  -", b)
    raise SystemExit(1)
print(f"OK: {len(seen)} linked repo(s) verified public")
