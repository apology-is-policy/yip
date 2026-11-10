package main

// A LINE is the shared place a group of checkouts talk through.
//
// It lives under ~/.yip/lines/<id>, outside every checkout, because
// checkouts are on different branches and a file committed on one is
// invisible to the others until merged -- which is the very thing a merge
// conversation is trying to coordinate.
//
// Membership is RECORDED at install time rather than derived from a naming
// convention: identity is keyed by the checkout's absolute path, so two
// sessions cannot be misconfigured into answering to the same name, and a
// peer's worktree is a known fact rather than a guess.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// activeLine is resolved once at startup; Root() reads it.
var activeLine string

func yipHome() string {
	if v := os.Getenv("YIP_HOME"); v != "" {
		return v
	}
	return filepath.Join(homeDir(), ".yip")
}

func lineDirFor(id string) string { return filepath.Join(yipHome(), "lines", id) }

// resolveLine finds the line a checkout belongs to. All worktrees of one
// repository share a git common dir, so they land on the same line with no
// configuration at all. Separate clones need --line to be grouped.
func resolveLine(cwd string) (id string, err error) {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	common, err := gitCommonDir(cwd)
	if err != nil {
		// Not a repo: fall back to the directory itself, so yip still works
		// somewhere unversioned.
		abs, aerr := filepath.Abs(cwd)
		if aerr != nil {
			return "", err
		}
		return lineID(abs), nil
	}
	return lineID(common), nil
}

// lineID is a readable name plus a short digest of the path, so two
// unrelated repositories with the same name cannot share a line by accident.
func lineID(path string) string {
	clean := filepath.Clean(path)
	name := filepath.Base(clean)
	if name == ".git" {
		name = filepath.Base(filepath.Dir(clean))
	}
	name = strings.TrimSuffix(name, ".git")
	name = slugify(name)
	sum := sha256.Sum256([]byte(clean))
	return name + "-" + hex.EncodeToString(sum[:])[:6]
}

func gitCommonDir(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--path-format=absolute", "--git-common-dir").Output()
	if err == nil {
		if p := strings.TrimSpace(string(out)); filepath.IsAbs(p) {
			return p, nil
		}
	}
	// Older git has no --path-format; the answer may be relative to the top.
	out, err = exec.Command("git", "-C", dir, "rev-parse", "--git-common-dir").Output()
	if err != nil {
		return "", err
	}
	p := strings.TrimSpace(string(out))
	if filepath.IsAbs(p) {
		return p, nil
	}
	top, terr := gitTopLevel(dir)
	if terr != nil {
		return "", terr
	}
	return filepath.Join(top, p), nil
}

// checkoutRoot is the key membership is recorded under: the worktree top, or
// the directory itself where there is no repository.
func checkoutRoot(cwd string) string {
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if top, err := gitTopLevel(cwd); err == nil {
		if r, err := filepath.EvalSymlinks(top); err == nil {
			return r
		}
		return top
	}
	abs, _ := filepath.Abs(cwd)
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r
	}
	return abs
}

// ------------------------------------------------------------- membership

type Members struct {
	Line    string            `json:"line"`
	Members map[string]string `json:"members"` // checkout path -> agent name
}

func membersPath() string { return filepath.Join(Root(), "members.json") }

func LoadMembers() Members {
	m := Members{Line: activeLine, Members: map[string]string{}}
	b, err := os.ReadFile(membersPath())
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, &m)
	if m.Members == nil {
		m.Members = map[string]string{}
	}
	return m
}

func SaveMembers(m Members) error {
	if err := EnsureRoot(); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return atomicReplace(membersPath(), append(b, '\n'))
}

func (m Members) AgentAt(path string) string { return m.Members[path] }

func (m Members) PathOf(agent string) string {
	for p, a := range m.Members {
		if a == agent {
			return p
		}
	}
	return ""
}

func (m Members) Names() []string {
	var out []string
	for _, a := range m.Members {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- install

// hookMarker identifies our hook entries so a re-install replaces them
// instead of stacking another copy. It is an explicit sentinel rather than
// anything derived from the command, because the binary's NAME and PATH are
// the user's to choose -- matching on those means a renamed or relocated
// binary silently duplicates its hooks on every install.
const hookMarker = "# yip-line-hook"

type installResult struct {
	Line      string
	Agent     string
	LineDir   string
	Bin       string
	McpPath   string
	HookPath  string
	Peers     []string
	Reinstall bool
	Seat      string   // non-empty when installed as a seat: its description
	Notes     []string // anything the operator should know about the result
}

// InstallOptions select a seat instead of path membership (codex only).
type InstallOptions struct {
	Seat    bool   // share this checkout without becoming its path member
	Profile string // write a Codex profile layer instead of this checkout's .codex/
	// WakeWindow (claude-rewake): how long after starting or ending a turn an
	// idle session stays wakeable. It becomes the hook's timeout. 0 = default.
	WakeWindow time.Duration
}

func Install(cwd, lineOverride, asOverride string, local bool) (*installResult, error) {
	return InstallRuntime(cwd, lineOverride, asOverride, local, "claude")
}
func InstallRuntime(cwd, lineOverride, asOverride string, local bool, runtime string) (*installResult, error) {
	return InstallWith(cwd, lineOverride, asOverride, local, runtime, InstallOptions{})
}

// InstallWith joins this checkout (or a Codex profile) to a line.
//
// A checkout has at most ONE path member: the identity a path-resolved runtime
// (Claude's hooks, a human's CLI) answers to there. Installing never replaces
// it. A Codex install whose config names its identity explicitly can instead
// take a SEAT -- automatically when the checkout already has a different
// member, or on request with --seat / --profile.
func InstallWith(cwd, lineOverride, asOverride string, local bool, runtime string, opts InstallOptions) (*installResult, error) {
	if runtime != "claude" && runtime != "claude-channels" && runtime != "claude-rewake" && runtime != "codex" {
		return nil, fmt.Errorf("runtime must be claude, claude-channels, claude-rewake or codex")
	}
	if opts.WakeWindow == 0 {
		opts.WakeWindow = defaultWakeWindow
	}
	if opts.WakeWindow < 2*rewakeMargin || opts.WakeWindow > 24*time.Hour {
		return nil, fmt.Errorf("--wake-window must be between %s and 24h", 2*rewakeMargin)
	}
	if (opts.Seat || opts.Profile != "") && runtime != "codex" {
		return nil, fmt.Errorf("--seat and --profile are Codex installs: Claude's hooks identify an agent by its checkout, so a Claude agent needs a checkout of its own")
	}
	if opts.Profile != "" && !validComponent(opts.Profile) {
		return nil, fmt.Errorf("profile name must be letters, digits, - or _")
	}
	if opts.Profile != "" && asOverride == "" {
		return nil, fmt.Errorf("--profile needs an explicit --as NAME: a profile seat has no checkout to name it after")
	}
	root := checkoutRoot(cwd)

	if lineOverride != "" {
		activeLine = slugify(lineOverride)
	} else {
		id, err := resolveLine(root)
		if err != nil {
			return nil, err
		}
		activeLine = id
	}
	if err := EnsureRoot(); err != nil {
		return nil, err
	}

	unlock, err := fileGuard(membersPath())
	if err != nil {
		return nil, err
	}
	defer unlock()
	agent := asOverride
	m := Members{Line: activeLine, Members: map[string]string{}}
	if err := readState(membersPath(), &m); err != nil {
		return nil, err
	}
	if m.Members == nil {
		return nil, fmt.Errorf("members map is null")
	}
	seats, err := loadSeatsStrict()
	if err != nil {
		return nil, err
	}
	root = recordedRoot(root, m, seats)
	owner := m.AgentAt(root)
	seatMode := opts.Seat || opts.Profile != ""
	if agent == "" {
		switch {
		case owner != "" && !seatMode:
			agent = owner // already a member; keep the name
		case seatMode:
			return nil, fmt.Errorf("a seat needs an explicit --as NAME")
		default:
			agent = slugify(filepath.Base(root))
		}
	}
	if !validComponent(agent) {
		return nil, fmt.Errorf("invalid agent name %q", agent)
	}
	// One checkout, one path member. Replacing it used to be silent: the
	// previous agent vanished from the line while its hooks -- which resolve
	// identity by path -- started answering to the new name.
	// A Codex owner never needed the path: its config names it. So a Claude
	// install moves it to a seat beside the new member instead of refusing,
	// and the two can be installed in either order.
	movedOwner := false
	if owner != "" && owner != agent && !seatMode {
		switch {
		case runtime == "codex":
			seatMode = true // a Codex config names its identity; share the checkout
		case isCodexIdentity(owner, root):
			if _, taken := seats.Seats[owner]; taken {
				return nil, fmt.Errorf("%q is both %s's member and a seat elsewhere; uninstall it first", owner, root)
			}
			movedOwner = true
		default:
			return nil, fmt.Errorf("%s already belongs to %q on line %s. Claude's hooks identify an agent by its checkout, so a second Claude identity needs its own worktree", root, owner, activeLine)
		}
	}
	// A name is one identity's. Claiming another's would make two sessions
	// answer to it, which is the thing membership exists to prevent.
	converting := false
	if p := m.PathOf(agent); p != "" {
		switch {
		case !seatMode && p != root:
			return nil, fmt.Errorf("the name %q on line %s already belongs to %s. If that registration is left over, remove it (from any folder): yip uninstall --as %s --line %s -- otherwise pass --as <other-name>", agent, activeLine, p, agent, activeLine)
		case seatMode && (p != root || opts.Profile != ""):
			return nil, fmt.Errorf("the name %q on line %s is the checkout member at %s. If that is left over, remove it (from any folder): yip uninstall --as %s --line %s -- otherwise pass --as <other-name>", agent, activeLine, p, agent, activeLine)
		case seatMode:
			converting = true // this checkout's member becomes a seat here
		}
	}
	prior, hadSeat := seats.Seats[agent]
	if hadSeat {
		switch {
		case !seatMode:
			return nil, fmt.Errorf("the name %q on line %s is a %s. If that is left over, remove it (from any folder): yip uninstall --as %s --line %s -- otherwise pass --as <other-name>", agent, activeLine, seatDescription(prior), agent, activeLine)
		case prior.Profile != opts.Profile || (opts.Profile == "" && prior.Workdir != root):
			return nil, fmt.Errorf("the name %q on line %s is already a %s. If that is left over, remove it (from any folder): yip uninstall --as %s --line %s -- otherwise pass --as <other-name>", agent, activeLine, seatDescription(prior), agent, activeLine)
		}
	}

	bin, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot locate this binary: %v", err)
	}
	if r, err := filepath.EvalSymlinks(bin); err == nil {
		bin = r
	}

	res := &installResult{
		Line: activeLine, Agent: agent, LineDir: Root(), Bin: bin,
		Reinstall: (!seatMode && owner == agent) || hadSeat,
	}

	if runtime == "codex" {
		warning, err := ensureCodexEndpoint(agent)
		if err != nil {
			return nil, err
		}
		if warning != "" {
			res.Notes = append(res.Notes, warning)
		}
		if opts.Profile != "" {
			if err := codexProfileFiles(opts.Profile, bin, activeLine, agent, false); err != nil {
				return nil, err
			}
			res.McpPath = codexProfilePath(opts.Profile)
			res.HookPath = res.McpPath + " (inline hooks)"
		} else {
			if err := codexFiles(root, bin, activeLine, agent, false); err != nil {
				return nil, err
			}
			res.McpPath = filepath.Join(root, ".codex", "config.toml")
			res.HookPath = filepath.Join(root, ".codex", "hooks.json")
		}
		// Writing the layer is not Codex loading it: an untrusted folder's
		// .codex/ is ignored. Ask Codex now, so the operator hears it here
		// rather than from a silent session. No Codex installed: say nothing.
		startDir := cwd
		if startDir == "" {
			startDir, _ = os.Getwd()
		}
		if loaded, why, err := codexLoadsYip(startDir, opts.Profile, agent); err == nil && !loaded {
			res.Notes = append(res.Notes, "NOT LOADED YET: "+why)
		}
	} else {
		switch runtime {
		case "claude-channels":
			if err := RegisterChannel(agent, false); err != nil {
				return nil, err
			}
			if err := configureChannel(root, bin, activeLine, agent); err != nil {
				return nil, err
			}
		case "claude-rewake":
			warning, err := ensureEndpoint(agent, "claude-rewake")
			if err != nil {
				return nil, err
			}
			if warning != "" {
				res.Notes = append(res.Notes, warning)
			}
			fallthrough
		default:
			if err := writeMCP(root, bin, activeLine, agent); err != nil {
				return nil, err
			}
		}
		res.McpPath = filepath.Join(root, ".mcp.json")

		hookFile := "settings.json"
		other := "settings.local.json"
		if local {
			hookFile, other = other, hookFile
		}
		// One checkout, one registration. Idempotence used to hold only WITHIN a
		// file, so `install` followed by `install --local` left BOTH live: six hook
		// execs per tool call, naming two binary paths that can disagree about
		// which build is current. Observed on a real checkout, and it made a dead
		// binary hard to attribute because two were configured.
		if err := stripHooks(root, other); err != nil {
			return nil, err
		}
		wake := time.Duration(0)
		if runtime == "claude-rewake" {
			wake = opts.WakeWindow
		}
		if err := writeClaudeHooks(root, bin, hookFile, activeLine, agent, wake); err != nil {
			return nil, err
		}
		res.HookPath = filepath.Join(root, ".claude", hookFile)
	}

	m.Line = activeLine
	if seatMode {
		seat := Seat{Agent: agent, Runtime: runtime, Profile: opts.Profile, Created: now()}
		if hadSeat {
			seat.Created = prior.Created
		}
		if opts.Profile == "" {
			seat.Workdir = root
		}
		seats.Seats[agent] = seat
		if err := saveSeats(seats); err != nil {
			return nil, err
		}
		if converting {
			delete(m.Members, root)
			res.Notes = append(res.Notes, fmt.Sprintf("%s no longer owns %s by path; it is now a seat there.", agent, root))
		} else if owner != "" && owner != agent && !opts.Seat && opts.Profile == "" && !hadSeat {
			res.Notes = append(res.Notes, fmt.Sprintf("%s belongs to %s; %s joined as a Codex seat beside it, so %s is unaffected.", root, owner, agent, owner))
		}
		res.Seat = seatDescription(seat)
	} else {
		if movedOwner {
			seats.Seats[owner] = Seat{Agent: owner, Runtime: "codex", Workdir: root, Created: now()}
			if err := saveSeats(seats); err != nil {
				return nil, err
			}
			res.Notes = append(res.Notes, fmt.Sprintf("%s was this checkout's member; it is now a Codex seat beside %s (its config names it, so nothing changes for it).", owner, agent))
		}
		m.Members[root] = agent
	}
	if err := SaveMembers(m); err != nil {
		return nil, err
	}
	for _, n := range LineNames() {
		if n != agent {
			res.Peers = append(res.Peers, n)
		}
	}
	return res, nil
}

// sameDir: two spellings of one directory -- letter case on a case-insensitive
// disk (macOS), a hard link, a bind mount. EvalSymlinks normalises symlinks
// but not case, so `cd ~/Strategies` and `cd ~/strategies` gave two "checkouts"
// and the first registration blocked the second as a different folder.
func sameDir(a, b string) bool {
	if a == b {
		return true
	}
	fa, ea := os.Stat(a)
	fb, eb := os.Stat(b)
	return ea == nil && eb == nil && os.SameFile(fa, fb)
}

// recordedRoot is the spelling under which this checkout is recorded on the
// line, as a member path or a seat's workdir; root itself if it is not.
func recordedRoot(root string, m Members, s Seats) string {
	if _, ok := m.Members[root]; ok {
		return root
	}
	for p := range m.Members {
		if sameDir(p, root) {
			return p
		}
	}
	for _, seat := range s.Seats {
		if seat.Workdir != "" && sameDir(seat.Workdir, root) {
			return seat.Workdir
		}
	}
	return root
}

// isCodexIdentity: is this agent demonstrably a Codex agent -- by its delivery
// record, or by this checkout's .codex/ config naming it? Anything less leaves
// it a path member, because moving a Claude identity would break its hooks.
func isCodexIdentity(agent, root string) bool {
	if ep, err := readEndpoint(agent); err == nil && ep.Runtime == "codex" {
		return true
	}
	if b, err := os.ReadFile(filepath.Join(root, ".codex", "config.toml")); err == nil {
		if block, _, err := codexManagedBlock(string(b)); err == nil && codexBlockAgent(block) == agent {
			return true
		}
	}
	return false
}

// linesHosting lists the lines on which this checkout has a member or a seat,
// read from recorded state. Uninstall uses it when no line is given: the line
// derived from a folder is NOT necessarily the one it joined (install --line),
// and uninstalling from the derived one left the real membership behind.
func linesHosting(root string) []string {
	ents, _ := os.ReadDir(filepath.Join(yipHome(), "lines"))
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(yipHome(), "lines", e.Name())
		var m Members
		var s Seats
		_ = readState(filepath.Join(dir, "members.json"), &m)
		_ = readState(filepath.Join(dir, "seats.json"), &s)
		r := recordedRoot(root, m, s)
		if m.Members[r] != "" || len(s.At(r)) > 0 {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// Uninstall removes integrations and line membership, never history.
//
// With neither agent nor profile it removes everything this checkout hosts:
// its path member and any seat sharing it. agent narrows that to one identity;
// profile removes a profile seat and touches no checkout.
func Uninstall(cwd string) error { return UninstallWith(cwd, "", "") }
func UninstallWith(cwd, agent, profile string) error {
	_, err := UninstallFrom(cwd, agent, profile)
	return err
}

// UninstallFrom is UninstallWith reporting where the integration was removed.
// An identity named with --as that is recorded somewhere else on the line is
// removed THERE: a registration left by an earlier attempt in another folder
// (or one that no longer exists) must not need a cd into it to clean up.
func UninstallFrom(cwd, agent, profile string) (string, error) {
	root := checkoutRoot(cwd)
	unlock, err := fileGuard(membersPath())
	if err != nil {
		return "", err
	}
	defer unlock()
	m := Members{Members: map[string]string{}}
	if err := readState(membersPath(), &m); err != nil {
		return "", err
	}
	seats, err := loadSeatsStrict()
	if err != nil {
		return "", err
	}
	root = recordedRoot(root, m, seats)
	if profile == "" && agent != "" && agent != m.AgentAt(root) && !contains(seats.At(root), agent) {
		seat, isSeat := seats.Seats[agent]
		switch {
		case m.PathOf(agent) != "":
			root = m.PathOf(agent)
		case isSeat && seat.Profile != "":
			profile = seat.Profile
		case isSeat && seat.Workdir != "":
			root = seat.Workdir
		default:
			return "", fmt.Errorf("%q is not on line %s", agent, activeLine)
		}
	}
	where := root
	if profile != "" {
		where = codexProfilePath(profile)
	}
	return where, uninstallLocked(root, agent, profile, m, seats)
}

func uninstallLocked(root, agent, profile string, m Members, seats Seats) error {
	if profile != "" {
		if err := codexProfileFiles(profile, "", "", agent, true); err != nil {
			return err
		}
		for name, s := range seats.Seats {
			if s.Profile == profile && (agent == "" || agent == name) {
				delete(seats.Seats, name)
			}
		}
		return saveSeats(seats)
	}
	owner := m.AgentAt(root)
	here := seats.At(root)
	if agent != "" && agent != owner && !contains(here, agent) {
		return fmt.Errorf("%q is not a member or seat of %s", agent, root)
	}
	if agent == "" || agent == owner {
		if err := stripMCP(root); err != nil {
			return err
		}
		for _, f := range []string{"settings.json", "settings.local.json"} {
			if err := stripHooks(root, f); err != nil {
				return err
			}
		}
	}
	// .codex/ serves exactly one identity: the member or a seat sharing root.
	if b, err := os.ReadFile(filepath.Join(root, ".codex", "config.toml")); err == nil {
		block, _, _ := codexManagedBlock(string(b))
		if agent == "" || codexBlockAgent(block) == agent {
			if err := codexFiles(root, "", "", "", true); err != nil {
				return err
			}
		}
	}
	for _, name := range here {
		if agent == "" || agent == name {
			delete(seats.Seats, name)
		}
	}
	if err := saveSeats(seats); err != nil {
		return err
	}
	if agent == "" || agent == owner {
		delete(m.Members, root)
	}
	return SaveMembers(m)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ------------------------------------------------- config file merging
//
// These MERGE rather than overwrite: a checkout may already have an MCP
// server or hooks of its own, and clobbering them would be a rude surprise
// from a tool whose whole job is coordination.

func readJSON(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %v", path, err)
	}
	if m == nil {
		return nil, fmt.Errorf("%s must contain a JSON object", path)
	}
	return m, nil
}

func writeJSON(path string, m map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicReplace(path, append(b, '\n'))
}

// writeMCP names the identity and line explicitly. Resolving them from the
// session's directory at runtime silently picked a DIFFERENT line whenever the
// install used --line: the folder's own derived line, which has no state.
func writeMCP(root, bin, line, agent string) error {
	path := filepath.Join(root, ".mcp.json")
	m, err := readJSON(path)
	if err != nil {
		return err
	}
	servers, _ := m["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers["yip"] = map[string]any{"command": bin, "args": []any{"serve", "--as", agent, "--line", line}}
	m["mcpServers"] = servers
	return writeJSON(path, m)
}

func stripMCP(root string) error {
	path := filepath.Join(root, ".mcp.json")
	m, err := readJSON(path)
	if err != nil {
		return err
	}
	servers, _ := m["mcpServers"].(map[string]any)
	if servers == nil {
		return nil
	}
	delete(servers, "yip")
	if len(servers) == 0 {
		delete(m, "mcpServers")
	}
	if len(m) == 0 {
		return os.Remove(path)
	}
	return writeJSON(path, m)
}

// hookCommand is guarded on the binary existing, so a checkout on a machine
// where yip is absent is unaffected rather than erroring on every tool call.
func hookCommand(bin, event string) string {
	return fmt.Sprintf("[ ! -x %s ] || %s hook %s  %s", bin, bin, event, hookMarker)
}

// claudeHookCommand is hookCommand with the identity and line named. The
// unnamed form resolves the line from the session's directory, which is a
// different (empty) line whenever install used --line: every hook then
// silently did nothing, including the Stop hook that holds an owed reply.
func claudeHookCommand(bin, event, line, agent string) string {
	return fmt.Sprintf("[ ! -x %s ] || %s hook %s --line %s --as %s  %s", bin, bin, event, shellQuote(line), shellQuote(agent), hookMarker)
}

// binFromHookCmd is hookCommand's inverse. The two are COUPLED BY FORMAT and
// nothing in the type system says so, which is why `doctor` asserts the round
// trip end-to-end rather than trusting this to keep matching.
func binFromHookCmd(cmd string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(cmd), "[ ! -x ")
	if !ok {
		return ""
	}
	bin, _, ok := strings.Cut(rest, " ]")
	if !ok {
		return ""
	}
	return bin
}

// configuredBins reports every distinct binary path this checkout's config
// names -- across .mcp.json AND both settings files.
//
// It exists because "the config names us" and "the thing it names can run" are
// different claims, and only the first was ever checked.
//
// MEASURED on macOS/arm64: overwriting the binary in place while a process is
// running from it can leave that path permanently SIGKILL-on-exec -- valid on
// disk, passing `codesign -v`, dead at every exec, and it does not clear when
// the holder exits. The symptom is `Killed: 9` inside a hook error, with
// nothing in the message naming yip. See the Makefile for the measurement.
func configuredBins(root string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if m, err := readJSON(filepath.Join(root, ".mcp.json")); err == nil {
		if servers, ok := m["mcpServers"].(map[string]any); ok {
			if y, ok := servers["yip"].(map[string]any); ok {
				cmd, _ := y["command"].(string)
				add(cmd)
			}
		}
	}
	for _, f := range []string{"settings.json", "settings.local.json"} {
		m, err := readJSON(filepath.Join(root, ".claude", f))
		if err != nil {
			continue
		}
		hooks, _ := m["hooks"].(map[string]any)
		for _, ev := range []string{"PostToolUse", "Stop", "SessionStart"} {
			arr, _ := hooks[ev].([]any)
			for _, g := range arr {
				if !isYipGroup(g) {
					continue
				}
				gm, _ := g.(map[string]any)
				hs, _ := gm["hooks"].([]any)
				for _, h := range hs {
					hm, _ := h.(map[string]any)
					cmd, _ := hm["command"].(string)
					add(binFromHookCmd(cmd))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// BinRuns answers only "does this exec at all". An exit code of -1 means the
// process was terminated by a SIGNAL, which is the whole point: a binary that
// runs and reports an error is fine here, one that never gets to report
// anything is not.
func BinRuns(bin string) (ok bool, detail string) {
	if st, err := os.Stat(bin); err != nil {
		return false, "missing"
	} else if st.Mode()&0o111 == 0 {
		return false, "not executable"
	}
	err := exec.Command(bin, "whoami").Run()
	if err == nil {
		return true, ""
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ProcessState.ExitCode() == -1 {
			return false, "killed by a signal -- reinstall it (see `make install`)"
		}
		return true, "" // ran, said no; that is not our question
	}
	return false, err.Error()
}

// BinVersion asks the wired binary what it is, so doctor can tell "runs" from
// "is the build you meant". Empty when it cannot answer -- a build older than
// the version subcommand, or a dead path (BinRuns reports that separately).
func BinVersion(bin string) string {
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// isRewakeGroup: a Yip group holding the claude-rewake background waiter.
func isRewakeGroup(group any) bool {
	g, _ := group.(map[string]any)
	hooks, _ := g["hooks"].([]any)
	for _, h := range hooks {
		hm, _ := h.(map[string]any)
		if cmd, _ := hm["command"].(string); strings.Contains(cmd, hookMarker) && strings.Contains(cmd, " hook rewake ") {
			return true
		}
	}
	return false
}

func isYipGroup(group any) bool {
	g, _ := group.(map[string]any)
	hooks, _ := g["hooks"].([]any)
	for _, h := range hooks {
		hm, _ := h.(map[string]any)
		if cmd, _ := hm["command"].(string); strings.Contains(cmd, hookMarker) {
			return true
		}
	}
	return false
}

// dropYipGroups makes install idempotent: a re-install replaces our entries
// instead of stacking a second copy on every run.
func dropYipGroups(existing any) []any {
	arr, _ := existing.([]any)
	var out []any
	for _, g := range arr {
		if !isYipGroup(g) {
			out = append(out, g)
		}
	}
	return out
}

// writeClaudeHooks replaces this file's Yip hook groups. wake > 0 adds the
// claude-rewake background waiter to SessionStart and Stop, as its own group
// so that its asyncRewake handler never shares a group with a blocking one.
func writeClaudeHooks(root, bin, file, line, agent string, wake time.Duration) error {
	path := filepath.Join(root, ".claude", file)
	m, err := readJSON(path)
	if err != nil {
		return err
	}
	hooks, _ := m["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	add := func(event, hookEvent string, matcher string) {
		group := map[string]any{
			"hooks": []any{map[string]any{"type": "command", "command": claudeHookCommand(bin, hookEvent, line, agent)}},
		}
		if matcher != "" {
			group["matcher"] = matcher
		}
		groups := append(dropYipGroups(hooks[event]), group)
		if wake > 0 && (event == "Stop" || event == "SessionStart") {
			groups = append(groups, map[string]any{"hooks": []any{rewakeHookEntry(bin, line, agent, wake)}})
		}
		hooks[event] = groups
	}
	add("PostToolUse", "posttooluse", "")
	add("Stop", "stop", "")
	add("SessionStart", "sessionstart", "startup|resume|compact")
	m["hooks"] = hooks
	return writeJSON(path, m)
}

func stripHooks(root, file string) error {
	path := filepath.Join(root, ".claude", file)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	m, err := readJSON(path)
	if err != nil {
		return err
	}
	hooks, _ := m["hooks"].(map[string]any)
	if hooks == nil {
		return nil
	}
	for _, ev := range []string{"PostToolUse", "Stop", "SessionStart"} {
		rest := dropYipGroups(hooks[ev])
		if len(rest) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = rest
		}
	}
	if len(hooks) == 0 {
		delete(m, "hooks")
	} else {
		m["hooks"] = hooks
	}
	if len(m) == 0 {
		return os.Remove(path)
	}
	return writeJSON(path, m)
}

// hookInstalled reports whether a checkout's config actually names us --
// "wrote the file" and "the file says what we meant" are different claims.
func hookInstalled(root string) (mcp bool, hooksIn []string) {
	if m, err := readJSON(filepath.Join(root, ".mcp.json")); err == nil {
		if servers, ok := m["mcpServers"].(map[string]any); ok {
			_, mcp = servers["yip"]
		}
	}
	// Every file is reported, NOT just the first. Two files can each carry a
	// full registration -- `install` then `install --local` used to leave both
	// -- and stopping at the first hides the duplicate that makes a broken
	// binary hard to attribute.
	for _, f := range []string{"settings.json", "settings.local.json"} {
		m, err := readJSON(filepath.Join(root, ".claude", f))
		if err != nil {
			continue
		}
		hooks, _ := m["hooks"].(map[string]any)
		n, wake := 0, 0
		for _, ev := range []string{"PostToolUse", "Stop", "SessionStart"} {
			arr, _ := hooks[ev].([]any)
			for _, g := range arr {
				switch {
				case isRewakeGroup(g):
					wake++
				case isYipGroup(g):
					n++
				}
			}
		}
		if n > 0 || wake > 0 {
			desc := fmt.Sprintf("%s (%d/3)", f, n)
			if wake > 0 {
				desc += fmt.Sprintf(" + rewake (%d/2)", wake)
			}
			hooksIn = append(hooksIn, desc)
		}
	}
	return
}
