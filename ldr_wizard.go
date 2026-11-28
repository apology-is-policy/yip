package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/apology-is-policy/yip/ldrclient"
)

const wizardUsage = `yip ldr wizard <step> --workspace <private directory> [options]
Set up a relay
  host        --url <https URL> [--tunnel]          (on the relay host)
  prepare     --in <host.yip> [--root-a <private key path>] [--root-b <path>] [--operator-key <path>]
  provision   --in <line.desc.cbor>                 (on the relay host)
  serve       [--listen <address>]                  (foreground on the relay host)
  initialize                                        (on the operator workstation)
Invite a workstation
  invite      (--setup <operator setup folder> | --admin-dir <admin client> --operator-key <path>) --namespace <name> [--actor-limit N] [--no-reader]
  review      --in <request.cbor>
  approve     --code <workstation comparison code>
  admit       --in <proof.cbor>
Join a line
  join        --in <invitation.yip>
  prove       --in <challenge.cbor>
  activate
Automated exchange through an authenticated, synced folder
  exchange-invite --exchange <folder> [--code <confirmed code>] [--wait]
  exchange-join   --exchange <folder> [--wait]
Progress
  status
Use one private workspace per setup, invitation or workstation. Transfer only the
named file in share/ over your chosen authenticated channel. Repeat a step to resume.
`

type wizardArgs struct {
	step, workspace, input                  string
	url, listen                             string
	rootA, rootB, operator, admin, setupDir string
	namespace, code, exchange               string
	limit                                   uint64
	tunnel, noReader, wait                  bool
}

func (a wizardArgs) path(name string) string   { return filepath.Join(a.workspace, name) }
func (a wizardArgs) shared(name string) string { return a.path(filepath.Join("share", name)) }
func wizardCLI(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprint(out, wizardUsage)
		return nil
	}
	a := wizardArgs{step: args[0]}
	f := flag.NewFlagSet(a.step, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&a.workspace, "workspace", "", "private wizard folder")
	role := ""
	switch a.step {
	case "host":
		role = "host"
		f.StringVar(&a.url, "url", "", "public HTTPS URL")
		f.BoolVar(&a.tunnel, "tunnel", false, "use a WebSocket tunnel")
	case "serve":
		role = "host"
		f.StringVar(&a.listen, "listen", "", "listener address override")
	case "provision":
		role = "host"
	case "prepare":
		role = "setup"
		f.StringVar(&a.rootA, "root-a", "", "first root key path")
		f.StringVar(&a.rootB, "root-b", "", "second root key path")
		f.StringVar(&a.operator, "operator-key", "", "operator key path")
	case "initialize":
		role = "setup"
	case "invite":
		role = "operator"
		f.StringVar(&a.setupDir, "setup", "", "operator setup folder")
		f.StringVar(&a.admin, "admin-dir", "", "operator client directory")
		f.StringVar(&a.operator, "operator-key", "", "operator signing key")
		f.StringVar(&a.namespace, "namespace", "", "workstation namespace")
		f.Uint64Var(&a.limit, "actor-limit", 4, "maximum actors")
		f.BoolVar(&a.noReader, "no-reader", false, "omit content access")
	case "review", "admit":
		role = "operator"
	case "approve":
		role = "operator"
		f.StringVar(&a.code, "code", "", "workstation comparison code")
	case "join", "prove", "activate":
		role = "workstation"
	case "exchange-invite", "exchange-join":
		role = "workstation"
		if a.step == "exchange-invite" {
			role = "operator"
			f.StringVar(&a.code, "code", "", "confirmed workstation code")
		}
		f.StringVar(&a.exchange, "exchange", "", "shared exchange directory")
		f.BoolVar(&a.wait, "wait", false, "wait up to two minutes for the other workstation")
	case "status":
	default:
		return fmt.Errorf("unknown wizard step %q\n%s", a.step, wizardUsage)
	}
	switch a.step {
	case "prepare", "provision", "review", "admit", "join", "prove":
		f.StringVar(&a.input, "in", "", "received file")
	}
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || a.workspace == "" {
		return errors.New(wizardUsage)
	}
	var err error
	a.workspace, err = ldrclient.CanonicalPath(a.workspace)
	if err != nil {
		return err
	}
	if err = wizardPrivateLocation(a.workspace); err != nil {
		return err
	}
	switch a.step {
	case "host", "prepare", "invite", "join", "exchange-join":
		if err = os.MkdirAll(a.workspace, 0700); err != nil {
			return err
		}
	}
	st, err := os.Stat(a.workspace)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("choose a private directory (mode 0700) for %s", a.workspace)
	}
	if a.step == "serve" {
		role, e := wizardRead(a.path("role"))
		if e != nil {
			return e
		}
		if string(role) != "host" {
			return errors.New("choose the relay host workspace")
		}
		var host wizardHost
		if e = wizardLoad(a.path("host.yip"), &host); e != nil {
			return e
		}
		if _, e = host.origin(); e != nil {
			return e
		}
		if _, e = wizardRead(a.path("provisioned")); e != nil {
			return fmt.Errorf("provision the signed line before starting: %w", e)
		}
		return RelayCLI(host.serveArgs(a.path("relay"), a.listen), out)
	}
	if a.step == "status" {
		b, err := wizardRead(a.path("next.txt"))
		if err != nil {
			return fmt.Errorf("no completed step in this workspace: %w", err)
		}
		_, err = out.Write(b)
		return err
	}
	unlock, err := fileGuard(a.path(".wizard"))
	if err != nil {
		return err
	}
	defer unlock()
	if exists, e := wizardExists(a.path("role")); e != nil {
		return e
	} else if !exists {
		entries, e := os.ReadDir(a.workspace)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if entry.Name() != ".wizard.lock" {
				return errors.New("choose an empty private workspace for a new wizard")
			}
		}
	}
	if err = wizardSave(a.path("role"), []byte(role)); err != nil {
		return fmt.Errorf("workspace belongs to another workflow: %w", err)
	}
	if err = os.MkdirAll(a.path("share"), 0700); err != nil {
		return err
	}
	var message string
	switch a.step {
	case "host", "prepare", "provision", "initialize":
		message, err = a.setup()
	case "exchange-invite", "exchange-join":
		message, err = a.exchangeFiles()
	case "invite", "review", "approve", "admit":
		message, err = a.inviting()
	default:
		message, err = a.joining()
	}
	if err != nil {
		return err
	}
	message += "\n"
	if err = atomicReplace(a.path("next.txt"), []byte(message)); err != nil {
		return err
	}
	if err = wizardSyncDir(a.workspace); err != nil {
		return err
	}
	_, err = io.WriteString(out, message)
	return err
}

// Read a bounded snapshot of a regular file before interpreting a received artifact.
func wizardRead(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("choose the file you received")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const limit = 1 << 20
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fmt.Errorf("expected a regular file of at most 1 MiB: %s", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(b) > limit {
		return nil, errors.New("wizard file exceeds 1 MiB")
	}
	return b, err
}

func wizardJSON(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("unexpected trailing wizard data")
	}
	return nil
}

func wizardSave(path string, b []byte) error {
	err := atomicCreate(path, b)
	if errors.Is(err, os.ErrExist) {
		old, e := wizardRead(path)
		if e != nil {
			return e
		}
		if !bytes.Equal(old, b) {
			return fmt.Errorf("different information already saved at %s", path)
		}
	} else if err != nil {
		return err
	}
	return wizardSyncDir(filepath.Dir(path))
}

func wizardSyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func wizardCopy(src, dst string) error {
	b, err := wizardRead(src)
	if err != nil {
		return err
	}
	return wizardSave(dst, b)
}

func wizardRecord(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return wizardSave(path, b)
}

func wizardLoad(path string, v any) error {
	b, err := wizardRead(path)
	if err != nil {
		return err
	}
	return wizardJSON(b, v)
}

func wizardExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Build an entire new client, including its signed request, before publishing either.
func wizardInitDir(dst string, build func(string) error) error {
	exists, err := wizardExists(dst)
	if err != nil || exists {
		return err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dst), ".initializing-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err = build(tmp); err != nil {
		return err
	}
	if err = wizardSyncDir(tmp); err != nil {
		return err
	}
	if err = os.Rename(tmp, dst); err != nil {
		return err
	}
	return wizardSyncDir(filepath.Dir(dst))
}

func wizardLDR(args ...string) error { return LDRCLI(args, io.Discard) }
func wizardCode(d [32]byte) string {
	h := fmt.Sprintf("%x", d[:12])
	return strings.Join([]string{h[:6], h[6:12], h[12:18], h[18:]}, "-")
}

func wizardContains(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Prevent an export folder from inadvertently becoming a key store.
func wizardPrivateLocation(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		if filepath.Base(p) == "share" {
			if ok, err := wizardExists(filepath.Join(filepath.Dir(p), ".wizard.lock")); err != nil {
				return err
			} else if ok {
				return errors.New("choose private storage outside the wizard's share folder")
			}
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}
