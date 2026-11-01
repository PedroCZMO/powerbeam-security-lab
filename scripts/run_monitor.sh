#!/usr/bin/env bash

set -euo pipefail
umask 077
shopt -s nullglob

LOG_DIR="/var/log/powerbeam"
MONITOR="/opt/powerbeam-monitor/scripts/security_monitor.py"
OUTPUT="/var/lib/powerbeam-monitor/alerts.jsonl"

files=("$LOG_DIR"/powerbeam.log*)

if (( ${#files[@]} == 0 )); then
    echo "ERROR: No se encontraron registros PowerBeam" >&2
    exit 1
fi

for file in "${files[@]}"; do
    if [[ ! -f "$file" || ! -r "$file" ]]; then
        echo "ERROR: Archivo no accesible: $file" >&2
        exit 1
    fi
done

for file in "${files[@]}"; do
    case "$file" in
        *.gz) gzip -dc -- "$file" ;;
        *) cat -- "$file" ;;
    esac
done | /usr/bin/python3 -B "$MONITOR" --output "$OUTPUT"
