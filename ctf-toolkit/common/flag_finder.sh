#!/bin/bash
# Flag Finder — Search for CTF flag patterns in files/directories
# Usage: ./flag_finder.sh [directory]

DIR="${1:-.}"

echo "==========================================="
echo "  Flag Finder — Scanning: $DIR"
echo "==========================================="

# Common flag patterns
PATTERNS=(
    "inctf{"
    "INCTF{"
    "InCTF{"
    "flag{"
    "FLAG{"
    "ctf{"
    "CTF{"
)

echo ""
echo "--- Searching files ---"
for pat in "${PATTERNS[@]}"; do
    results=$(grep -rl "$pat" "$DIR" 2>/dev/null)
    if [ -n "$results" ]; then
        echo ""
        echo "[+] Pattern: $pat"
        echo "$results" | while read -r f; do
            echo "    File: $f"
            grep -n "$pat" "$f" | head -5 | sed 's/^/    → /'
        done
    fi
done

echo ""
echo "--- Searching in binary files ---"
find "$DIR" -type f | while read -r f; do
    for pat in "${PATTERNS[@]}"; do
        if strings "$f" 2>/dev/null | grep -q "$pat"; then
            echo "[+] Binary match in: $f"
            strings "$f" | grep "$pat" | head -3 | sed 's/^/    → /'
        fi
    done
done

echo ""
echo "--- Searching environment / processes ---"
env 2>/dev/null | grep -iE "flag|ctf" | head -5
# Check /tmp, common flag locations
for loc in /flag /flag.txt /home/*/flag* /root/flag* /tmp/flag*; do
    if [ -f "$loc" ] 2>/dev/null; then
        echo "[+] Flag file: $loc"
        cat "$loc" 2>/dev/null | head -3
    fi
done

echo ""
echo "--- Quick network check ---"
# Check if flag is served on localhost
for port in 80 8080 1337 4444 5000 8000 9090; do
    (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null && echo "[*] Port $port is open"
done

echo ""
echo "==========================================="
echo "  Manual flag locations to check:"
echo "    /flag, /flag.txt, /home/ctf/flag.txt"
echo "    /root/flag.txt, /opt/flag.txt"
echo "    Environment: echo \$FLAG"
echo "    Memory: strings /proc/*/maps"
echo "==========================================="
