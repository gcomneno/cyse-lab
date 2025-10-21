#!/usr/bin/env bash
set -euo pipefail

outdir="tools/outputs"
mkdir -p "$outdir"

ts=$(date +%Y%m%d_%H%M%S)
echo "=== ENUM START $ts ===" > "$outdir/enum_${ts}.txt"
echo "HOSTNAME:" >> "$outdir/enum_${ts}.txt"
hostname >> "$outdir/enum_${ts}.txt" 2>&1
echo -e "\nUNAME:" >> "$outdir/enum_${ts}.txt"
uname -a >> "$outdir/enum_${ts}.txt" 2>&1
echo -e "\nIP ADDRESSES:" >> "$outdir/enum_${ts}.txt"
ip a >> "$outdir/enum_${ts}.txt" 2>&1
echo -e "\nSS:" >> "$outdir/enum_${ts}.txt"
ss -tunelp >> "$outdir/enum_${ts}.txt" 2>&1 || ss -tulpen >> "$outdir/enum_${ts}.txt" 2>&1 || true
echo -e "\nDF:" >> "$outdir/enum_${ts}.txt"
df -h >> "$outdir/enum_${ts}.txt" 2>&1
echo -e "\nWHOAMI / ID:" >> "$outdir/enum_${ts}.txt"
whoami >> "$outdir/enum_${ts}.txt" 2>&1
echo "=== ENUM END $ts ===" >> "$outdir/enum_${ts}.txt"

echo "Saved -> $outdir/enum_${ts}.txt"
