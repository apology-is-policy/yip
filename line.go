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
}

func Install(cwd, lineOverride, asOverride string, local bool) (*installResult, error) {
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

	agent := asOverride
	m := LoadMembers()
	if agent == "" {
		if a := m.AgentAt(root); a != "" {
			agent = a // already a member; keep the name
		} else {
			agent = slugify(filepath.Base(root))
		}
	}
	// A name is one checkout's. Claiming another's would make two sessions
	// answer to it, which is the thing membership exists to prevent.
	if p := m.PathOf(agent); p != "" && p != root {
		return nil, fmt.Errorf("the name %q on line %s already belongs to %s -- pass --as <other-name>", agent, activeLine, p)
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
		Reinstall: m.AgentAt(root) != "",
	}

	if err := writeMCP(root, bin); err != nil {
		return nil, err
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
	if err := writeHooks(root, bin, hookFile); err != nil {
		return nil, err
	}
	res.HookPath = filepath.Join(root, ".claude", hookFile)

	m.Line = activeLine
	m.Members[root] = agent
	if err := SaveMembers(m); err != nil {
		return nil, err
	}
	for _, n := range m.Names() {
		if n != agent {
			res.Peers = append(res.Peers, n)
		}
	}
	return res, nil
}

func Uninstall(cwd string) error {
	root := checkoutRoot(cwd)
	if err := stripMCP(root); err != nil {
		return err
	}
	for _, f := range []string{"settings.json", "settings.local.json"} {
		if err := stripHooks(root, f); err != nil {
			return err
		}
	}
	m := LoadMembers()
	delete(m.Members, root)
	return SaveMembers(m)
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

func writeMCP(root, bin string) error {
	path := filepath.Join(root, ".mcp.json")
	m, err := readJSON(path)
	if err != nil {
		return err
	}
	servers, _ := m["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers["yip"] = map[string]any{"command": bin, "args": []any{"serve"}}
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

func writeHooks(root, bin, file string) error {
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
			"hooks": []any{map[string]any{"type": "command", "command": hookCommand(bin, hookEvent)}},
		}
		if matcher != "" {
			group["matcher"] = matcher
		}
		hooks[event] = append(dropYipGroups(hooks[event]), group)
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
		n := 0
		for _, ev := range []string{"PostToolUse", "Stop", "SessionStart"} {
			arr, _ := hooks[ev].([]any)
			for _, g := range arr {
				if isYipGroup(g) {
					n++
				}
			}
		}
		if n > 0 {
			hooksIn = append(hooksIn, fmt.Sprintf("%s (%d/3)", f, n))
		}
	}
	return
}
