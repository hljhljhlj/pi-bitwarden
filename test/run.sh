#!/usr/bin/env bash
# End-to-end tests for the pi-bitwarden extension, fully headless:
# mock bw CLI + mock zenity + mock wl-copy (see test/mocks/).
#
# Each scenario runs a real `pi --no-session --mode json` session in a fresh
# temp dir and asserts on TOOL RESULT EVENTS, never on the model's prose
# (models paraphrase or hallucinate summaries; tool events are authoritative).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export BW_MOCK_DIR="$(mktemp -d /tmp/pi-bw-test.XXXXXX)"
export PATH="$ROOT/test/mocks/bin:$PATH"
PI="${PI_BIN:-pi}"
PASS=0; FAIL=0

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
check() { # check <description> <haystack-file> <grep-args...>
	local desc="$1" hay="$2"; shift 2
	if grep -q "$@" "$hay"; then ok "$desc"; else bad "$desc (wanted: $*)"; fi
}
count_eq() { # count_eq <description> <file> <expected> <pattern>
	local desc="$1" file="$2" want="$3" pat="$4"
	local got; got=$(grep -c -- "$pat" "$file" 2>/dev/null || true)
	[[ -z "$got" ]] && got=0
	[[ "$got" == "$want" ]] && ok "$desc ($got)" || bad "$desc (got $got, want $want)"
}

# pi --mode json output -> normalized tool-result lines: "TOOL <name> OK|ERR <text>"
normalize_events() {
	python3 "$ROOT/test/normalize_events.py"
}

# run_scenario <name> <env-passthrough (may be empty)> <prompt...>
run_scenario() {
	local name="$1" envs="$2"; shift 2
	local cwd; cwd="$(mktemp -d "$BW_MOCK_DIR/cwd-$name.XXXX")"
	( cd "$cwd" && env $envs timeout 300 "$PI" --no-session --mode json -p "$*" 2>&1 ) \
		| normalize_events > "$BW_MOCK_DIR/$name.events"
}

# ---------------------------------------------------------------- S1: load
say "S1: extension loads, bash override intact"
run_scenario s1 "" "Use the bash tool to run exactly: echo BWEXT_OK"
check "extension loads + bash works" "$BW_MOCK_DIR/s1.events" -q "TOOL bash OK .*BWEXT_OK"

# ------------------------------------------------- S2: unauthenticated hint
say "S2: friendly hint when bw CLI not logged in (no password prompt)"
rm -f "$BW_MOCK_DIR/pw-prompts"
run_scenario s2 "BW_MOCK_UNAUTH=1" "Call bw_list"
check "friendly not-logged-in hint" "$BW_MOCK_DIR/s2.events" -q "TOOL bw_list ERR .*not logged in"
count_eq "no master-password prompt" "$BW_MOCK_DIR/pw-prompts" "0" "."

# ------------------------------------------------- S3: happy path, one unlock
say "S3: list → inject → env → scrub → base64-scrub → clipboard (ONE unlock)"
rm -f "$BW_MOCK_DIR/pw-prompts" "$BW_MOCK_DIR/unlocks" "$BW_MOCK_DIR/clipboard"
run_scenario s3 "" 'Do exactly these 7 steps in order:
1) bw_list
2) bw_inject item TestService field password env T1
3) bash: echo LEN=${#T1}
4) bash: printenv T1
5) bw_inject item TestService field field:API_KEY env T2
6) bash: echo $T2 | base64
7) bw_clipboard item TestService'
check "bw_list shows items, not passwords" "$BW_MOCK_DIR/s3.events" -q "TOOL bw_list OK .*user: alice"
check "bw_list leaks no password" "$BW_MOCK_DIR/s3.events" -v -q "supersecret-value-123"
check "inject confirms env var" "$BW_MOCK_DIR/s3.events" -q "TOOL bw_inject OK .*Injected \$T1"
check "env var really injected (LEN=21)" "$BW_MOCK_DIR/s3.events" -q "TOOL bash OK .*LEN=21"
check "printenv scrubbed in result event" "$BW_MOCK_DIR/s3.events" -q "TOOL bash OK .*BW_SCRUBBED:T1"
check "base64 scrubbed in result event" "$BW_MOCK_DIR/s3.events" -q "TOOL bash OK .*BW_SCRUBBED-B64:T2"
check "no raw secret in any result event" "$BW_MOCK_DIR/s3.events" -v -q "supersecret-value-123"
check "no b64 secret in any result event" "$BW_MOCK_DIR/s3.events" -v -q "aGZfc2stYWJjOTg3eHl6NDU2"
check "clipboard tool confirms" "$BW_MOCK_DIR/s3.events" -q "TOOL bw_clipboard OK .*Copied \"TestService\""
check "clipboard really contains secret" "$BW_MOCK_DIR/clipboard" -q "supersecret-value-123"
count_eq "master password prompted ONCE per session" "$BW_MOCK_DIR/pw-prompts" "1" "."
count_eq "bw unlock ran ONCE per session" "$BW_MOCK_DIR/unlocks" "1" "."

# ------------------------------------------------- S4: deny path fail-closed
say "S4: user declines → fail closed"
run_scenario s4 "BW_MOCK_DENY=1" "Call bw_inject item TestService env D1, then bw_reveal item TestService reason test."
check "inject declined" "$BW_MOCK_DIR/s4.events" -q "TOOL bw_inject ERR .*User declined the injection"
check "reveal declined" "$BW_MOCK_DIR/s4.events" -q "TOOL bw_reveal ERR .*User declined the reveal"
check "nothing injected on deny" "$BW_MOCK_DIR/s4.events" -v -q "TOOL bw_inject OK"

# ------------------------------------------------- S5: reveal allow path
say "S5: bw_reveal allow path (confirmation mocked to allow)"
run_scenario s5 "" "Call bw_reveal item TestService field field:API_KEY reason citest"
check "reveal returned secret in tags" "$BW_MOCK_DIR/s5.events" -q "TOOL bw_reveal OK .*<secret>hf_sk-abc987xyz456</secret>"

# ------------------------------------------------- summary
say "RESULT: $PASS passed, $FAIL failed"
if [[ "$FAIL" -gt 0 ]]; then
	echo "events and mocks kept for debugging: $BW_MOCK_DIR"
else
	rm -rf "$BW_MOCK_DIR"
fi
[[ "$FAIL" -eq 0 ]]
