#!/usr/bin/env bash
# Convenience launcher for K-9.
#   ./k9-run.sh                 scan the current LAN
#   ./k9-run.sh --deep          full port sweep
#   ./k9-run.sh --web           live dashboard
#   sudo ./k9-run.sh            (optional) enables true ARP sweep if scapy present
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/k9.py" "$@"
