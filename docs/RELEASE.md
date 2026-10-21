# Building, installing and qualifying a release

Yip is MIT-licensed and uses Go's standard library. The module path is
`github.com/apology-is-policy/yip`. Source builds need Go 1.25+, Git and a Unix
host; Switchboard additionally uses a terminal and `stty`. Python 3.11+ is used
by packaging/integration tests, not by the installed Yip binary.

Supported build targets are macOS and Linux on arm64/amd64. Native Windows is
not supported. Cross-compilation proves buildability only; inspect the relevant
verification record before claiming a target/runtime was exercised.

```sh
make test
python3 scripts/release.py --version YOUR_VERSION --out /absolute/output
```

`GO=/path/to/go` selects the compiler. `--targets darwin/arm64` can build a subset.
The release builder does not publish, tag or push anything. It refuses existing
archive/checksum names, uses fixed archive timestamps, and emits `BUILD.json`
with compiler/version and per-file Go source hashes plus `SHA256SUMS`. Use the
same toolchain and source to reproduce binaries. The builder checks free space
before each target, preserving this deployment's 8 GiB floor. A completed target
can remain if a later target fails; do not call a partial set a complete release.

Each archive includes the binary, license, README, operating/resource guides,
example config and an installer. Verify SHA256SUMS against your trusted release
source before extracting/running it. The checksums are integrity evidence, not
a signature or proof of publisher identity. No signed release is claimed.

```sh
sh scripts/install-binary.sh ./yip "$HOME/.local/bin/yip"
yip version
yip --help
yip --help-agents
```

The installer stages and executes a new inode before renaming it into place,
backing up an existing executable. This avoids in-place writes to a running
macOS binary. It does not alter runtime integration, line state, permissions or
trust. Restart old MCP/hook clients at the coordinated upgrade boundary; their
running processes retain the old executable. `make install` also avoids in-place
overwrite, but is intended for source builds.

To remove runtime integration and membership, run `yip uninstall` in that
checkout after stopping its session/dispatcher. This retains line/resource
history and does not release leases for you. To remove the executable, remove
only the installed binary after clients stop. Do not delete `~/.yip`, line state
or lock files as an uninstall shortcut. Old executable backups allow a binary
rollback; never overwrite newer coordination state with an older snapshot.

## Runtime qualification

Claude Channels is a research-preview transport requiring explicit startup and
a received-probe acknowledgment. Yip is not an allowlisted public plugin.
Codex delivery uses the installed client's `queue` command and an exact opted-in
chat UUID. Neither fake transports nor protocol simulators prove live idle/busy
behavior. See [delivery-and-broadcasts](delivery-and-broadcasts.md).

The optional tmux transport uses an explicit private socket path, exact pane ID
and recorded process PID/start identity. It refuses shells/wrappers, dead panes,
copy mode and changed processes. Start the pane with `exec claude` or `exec codex`.
Registration never redirects an existing endpoint; use another identity when a
process is replaced. This path has no automatic fallback or watch loop:

```sh
yip delivery register-tmux --socket /absolute/tmux.socket --pane %1
# Verify this exact pane is idle at its normal empty input prompt:
yip delivery dispatch-tmux --confirm-idle
```

`--replay` on first registration includes existing records. `--confirm-idle` is
an assertion by the caller, not detection of runtime prompt state. The same
process may display a dialog; Yip cannot infer that from tmux. No Escape/Ctrl-C or
approval keys are injected. Text is literal, followed by Enter. Partial sends
are uncertain and never automatically retried; inspect the pane before retrying.
This is an explicitly selected alternative for controlled setups, with stronger
limitations than Channels. Keep paused and retired identities paused.

## Release gate

Before a public release: run tests on real macOS and Linux hosts, qualify the
actual opted-in Claude/Codex clients, review help/config/migration behavior,
verify the clean install/uninstall tests, and review the resulting diff and
archive checksums. CI configuration is supplied; its presence does not mean a
remote CI run passed. Publish/tag only the reviewed source and artifacts.
