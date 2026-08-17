#!/bin/bash
# End-to-end exercise of the new yip verbs, in an isolated line.
Y=/tmp/yiptest
export YIP_ROOT=/tmp/yip-e2e
rm -rf "$YIP_ROOT"; mkdir -p "$YIP_ROOT"
fails=0
ck()  { if printf '%s' "$3" | grep -qF "$2"; then echo "PASS $1"
        else echo "FAIL $1: wanted '$2', got: $(printf '%s' "$3" | head -2)"; fails=$((fails+1)); fi; }
ckn() { if printf '%s' "$3" | grep -qF "$2"; then echo "FAIL $1: should NOT have '$2'"; fails=$((fails+1))
        else echo "PASS $1"; fi; }
cke() { if [ "$2" -eq "$3" ]; then echo "PASS $1 (exit $3)"
        else echo "FAIL $1: wanted exit $2, got $3"; fails=$((fails+1)); fi; }

seed() { printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}" \
  | $Y serve --as "$3" 2>/dev/null; }

echo "=== 1. seed a call ==="
$Y init --as aux >/dev/null 2>&1
seed call '{"peer":"main","subject":"the test matter","body":"first turn from aux"}' aux >/dev/null
ck "call exists" "the-test-matter" "$($Y calls --as aux 2>&1)"

echo "=== 2. watch --replay reports what is there, for the PEER ==="
out=$($Y watch --as main --once --replay --interval 200ms --timeout 5s 2>&1)
ck "sees the call"   "CALL"       "$out"
ck "sees the turn"   "TURN"       "$out"
ck "names the floor" "floor:main" "$out"

echo "=== 3. you are NOT woken by your own writes (assert the EXIT, not an absence) ==="
$Y watch --as aux --once --replay --interval 200ms --timeout 2s >/dev/null 2>&1
cke "aux waited and got nothing" 3 $?

echo "=== 3b. --once is BOUNDED (the unbounded-waiter hazard it exists to fix) ==="
s=$(date +%s); $Y watch --as aux --once --interval 200ms --timeout 2s >/dev/null 2>&1; e=$(($(date +%s)-s))
if [ "$e" -lt 20 ]; then echo "PASS --once gave up after ${e}s"
else echo "FAIL --once ran ${e}s, unbounded"; fails=$((fails+1)); fi

echo "=== 4. a note leaves the floor alone ==="
ck "floor before" "floor: main" "$($Y read --as main 2>&1 | tail -1)"
echo "a one-way correction" | $Y note --as main >/dev/null 2>&1
ck "floor UNCHANGED after note" "floor: main" "$($Y read --as main 2>&1 | tail -1)"

echo "=== 5. ratify is a HUMAN turn, and agents have no verb for it ==="
echo "approved: renumber to 104/105" | $Y ratify --as main --by michal >/dev/null 2>&1
ck "recorded as human" "kind: human" "$(cat "$YIP_ROOT"/calls/*/notes/*michal*.md 2>/dev/null)"
tools=$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | $Y serve --as aux 2>/dev/null)
ckn "NO ratify tool exists" '"ratify"' "$tools"
ck  "note IS a tool"        '"note"'   "$tools"
ck  "dispute IS a tool"     '"dispute"' "$tools"

echo "=== 6. watch marks the human turn distinctly ==="
ck "HUMAN event" "HUMAN" "$($Y watch --as aux --once --replay --interval 200ms --timeout 5s 2>&1)"

echo "=== 7. same measurement -> AGREED, nobody else needed ==="
$Y dispute --as aux "does exec c read page budget" >/dev/null 2>&1
ck "starts unmeasured" "neither side has named" "$($Y dispute --as aux 2>&1)"
$Y measure --as aux 001 "git grep -c page_budget kernel/exec.c" >/dev/null 2>&1
ck "waits for peer" "WAITING on main" "$($Y dispute --as aux 2>&1)"
$Y measure --as main 001 "git grep -c page_budget kernel/exec.c" >/dev/null 2>&1
out=$($Y dispute --as aux 2>&1)
ck "agreed" "AGREED" "$out"; ck "no human needed" "no human needed" "$out"

echo "=== 8. BOTH say none -> ESCALATE (the case that must not read as agreement) ==="
$Y dispute --as aux "is this worth building at all" >/dev/null 2>&1
$Y measure --as aux  002 none >/dev/null 2>&1
$Y measure --as main 002 none >/dev/null 2>&1
out=$($Y dispute --as aux 2>&1)
ck "escalates"    "ESCALATE"             "$out"
ck "says why"     "belongs to the human" "$out"
# Scope to dispute 002's own block. A multi-line `grep -F` pattern is treated
# as SEVERAL patterns OR'd together, not one -- so an unscoped check here
# matched dispute 001's perfectly legitimate AGREED and failed a correct code.
d2=$(printf '%s' "$out" | sed -n '/^002-/,/^00[3-9]-/p')
ckn "002 NOT reported as agreement" "AGREED" "$d2"

echo "=== 9. one side none -> PARTIAL ==="
$Y dispute --as aux "partial case" >/dev/null 2>&1
$Y measure --as aux  003 "ls -l" >/dev/null 2>&1
$Y measure --as main 003 none    >/dev/null 2>&1
ck "partial" "PARTIAL" "$($Y dispute --as aux 2>&1)"

echo "=== 10. different measurements -> run both ==="
$Y dispute --as aux "how many hunks conflict" >/dev/null 2>&1
$Y measure --as aux  004 "git merge-tree --write-tree a b" >/dev/null 2>&1
$Y measure --as main 004 "git merge-file -p o b t" >/dev/null 2>&1
ck "differ" "DIFFER" "$($Y dispute --as aux 2>&1)"

echo "=== 11. attach is a SNAPSHOT ==="
echo "the union list" > /tmp/yip-artifact.txt
seed attach '{"path":"/tmp/yip-artifact.txt"}' aux >/dev/null 2>&1
ck "artifact crossed" "the union list" "$(cat "$YIP_ROOT"/calls/*/attachments/* 2>/dev/null)"
echo "MUTATED AFTER SENDING" > /tmp/yip-artifact.txt
ckn "cannot change under the reader" "MUTATED" "$(cat "$YIP_ROOT"/calls/*/attachments/* 2>/dev/null)"

echo "=== 12. doctor checks the configured binary RUNS, not just that it is named ==="
# The real specimen is a binary overwritten in place while mapped, which on
# macOS can end up permanently SIGKILLed at exec. That reproduction is NOT
# deterministic (1 of 4 attempts did not take), and a flaky gate is worse than
# no gate -- so the specimen here is a script that kills itself, which reaches
# the same branch (`ExitCode() == -1`, terminated by a signal) every time.
D=/tmp/yip-doctor-test
rm -rf $D; mkdir -p $D/.claude
printf '#!/bin/sh\nkill -9 $$\n' > $D/badbin && chmod +x $D/badbin
printf '{"mcpServers":{"yip":{"command":"%s","args":["serve"]}}}\n' "$D/badbin" > $D/.mcp.json
out=$(cd $D && $Y doctor --as probe 2>&1)
ck "names the dead binary"  "DOES NOT RUN"      "$out"
ck "says a signal killed it" "killed by a signal" "$out"
# The control matters as much as the specimen: a detector that reports
# everything dead would pass the assertion above and be useless.
printf '{"mcpServers":{"yip":{"command":"%s","args":["serve"]}}}\n' "$Y" > $D/.mcp.json
out=$(cd $D && $Y doctor --as probe 2>&1)
ckn "a WORKING binary is not reported dead" "DOES NOT RUN" "$out"
# "runs" is not "is this build". Two real installs three weeks apart both ran
# and both said 0.1.0. The wired binary must report the SAME version as the
# doctor asking, or be named STALE with both paths.
ck  "the same build is reported current" "current" "$out"
ckn "the same build is not STALE" "STALE" "$out"

echo "=== 13. doctor tells a stale wired binary from the current one ==="
# The specimen: a binary that runs fine and answers `version` with something
# else. That is exactly what an older real install looks like from here.
printf '#!/bin/sh\ncase "$1" in version) echo 0.0.0-elsewhere;; *) exit 0;; esac\n' > $D/oldbin && chmod +x $D/oldbin
printf '{"mcpServers":{"yip":{"command":"%s","args":["serve"]}}}\n' "$D/oldbin" > $D/.mcp.json
out=$(cd $D && $Y doctor --as probe 2>&1)
ck  "names the stale binary"        "STALE"           "$out"
ck  "quotes its version"            "0.0.0-elsewhere" "$out"
ckn "and does not call it dead"     "DOES NOT RUN"    "$out"

echo; echo "=========================================="
if [ "$fails" -eq 0 ]; then echo "ALL PASS"; else echo "$fails FAILED"; fi
exit $fails
