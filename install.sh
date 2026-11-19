#!/usr/bin/env bash
# Dev install: symlink the extension into pi's global extensions dir.
# Edits in this repo take effect on the next /reload inside pi.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
EXT_DIR="$HOME/.pi/agent/extensions"
mkdir -p "$EXT_DIR" "$HOME/.bw/pi-extension"
ln -sfn "$DIR/bitwarden.ts" "$EXT_DIR/bitwarden.ts"
if [[ ! -f "$HOME/.bw/pi-extension/config.json" ]]; then
	cp "$DIR/config.example.json" "$HOME/.bw/pi-extension/config.json"
	echo "Created ~/.bw/pi-extension/config.json (defaults)"
fi
echo "Installed: $EXT_DIR/bitwarden.ts -> $EXT_DIR/bitwarden.ts"
echo "Requires: bw CLI logged in (bw login), zenity for desktop prompts."
