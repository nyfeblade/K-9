#!/usr/bin/env bash
# Convenience launcher for ViperScan.
#   ./viperscan-run.sh                 scan the current LAN
#   ./viperscan-run.sh --deep          full port sweep
#   ./viperscan-run.sh --web           live dashboard
#   sudo ./viperscan-run.sh            (optional) enables true ARP sweep if scapy present
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/viperscan.py" "$@"
