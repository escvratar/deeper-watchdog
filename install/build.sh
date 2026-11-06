#!/bin/sh
# Builds the release files into dist/: installers for Linux and Windows (the target installer dw-install.sh
# embedded), portable versions for Linux and Windows (with embedded Python), and copies the APK if built.
#   install/build.sh            (run from anywhere; the Windows Python is downloaded once into install/.cache)
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/dist
CACHE=$ROOT/install/.cache
PYV=${PYV:-3.13.17}
rm -rf "$OUT" && mkdir -p "$OUT" "$CACHE"

payload=$(gzip -9nc "$ROOT/install/dw-install.sh" | base64 | tr -d '\n')
crlf() { sed 's/\r$//; s/$/\r/'; }

# The target installer as is (curl ... | sh on the device itself)
cp "$ROOT/install/dw-install.sh" "$OUT/dw-install.sh"

# Linux / macOS
sed "s|@@PAYLOAD@@|$payload|" "$ROOT/install/install-linux.sh" > "$OUT/deeper-watchdog-install-linux.sh"
chmod +x "$OUT/deeper-watchdog-install-linux.sh"

# Windows: one .bat that runs its own PowerShell part
{ cat "$ROOT/install/windows-header.bat"; sed "s|@@PAYLOAD@@|$payload|" "$ROOT/install/install-windows.ps1"; } | crlf \
    > "$OUT/deeper-watchdog-install-windows.bat"

# Portable Linux
T=$(mktemp -d)
mkdir "$T/deeper-watchdog"
cp "$ROOT/deeper_watchdog.py" "$ROOT/portable/linux/run.sh" "$ROOT/portable/linux/README.txt" "$T/deeper-watchdog/"
chmod +x "$T/deeper-watchdog/run.sh"
tar -C "$T" --owner=0 --group=0 -czf "$OUT/deeper-watchdog-portable-linux.tar.gz" deeper-watchdog
rm -rf "$T"

# Portable Windows: Python embeddable (no installation, no admin rights)
zip="$CACHE/python-$PYV-embed-amd64.zip"
[ -f "$zip" ] || curl -fsSL -o "$zip" "https://www.python.org/ftp/python/$PYV/python-$PYV-embed-amd64.zip"
T=$(mktemp -d)
mkdir -p "$T/deeper-watchdog/python"
(cd "$T/deeper-watchdog/python" && unzip -q "$zip")
cp "$ROOT/deeper_watchdog.py" "$T/deeper-watchdog/"
for f in "$ROOT"/portable/windows/*.bat; do crlf < "$f" > "$T/deeper-watchdog/$(basename "$f")"; done
cp "$ROOT/portable/windows/winctl.py" "$T/deeper-watchdog/"
# Notepad wants a BOM to show UTF-8 Russian text
{ printf '\357\273\277'; crlf < "$ROOT/portable/windows/README.txt"; } > "$T/deeper-watchdog/README.txt"
(cd "$T" && python3 -c "
import os, zipfile
with zipfile.ZipFile('$OUT/deeper-watchdog-portable-windows.zip', 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for d, _, fs in os.walk('deeper-watchdog'):
        for f in sorted(fs):
            z.write(os.path.join(d, f))
")
rm -rf "$T"

[ -f "$ROOT/android/build/deeper-watchdog.apk" ] && cp "$ROOT/android/build/deeper-watchdog.apk" "$OUT/"
(cd "$OUT" && sha256sum -- * > SHA256SUMS.txt)
ls -l "$OUT"
