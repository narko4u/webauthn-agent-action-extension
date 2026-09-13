#!/usr/bin/env bash
# Repo-specific checks for webauthn-agent-action-extension
set -euo pipefail

# Installs the package and its declared test dependencies, then runs the suite.
python3 -m pip install --quiet --disable-pip-version-check -e ".[test]"
python3 -m pytest -q
