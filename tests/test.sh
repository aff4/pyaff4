#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."
python -m unittest discover -s tests -t . -p 'test_*.py' -v
