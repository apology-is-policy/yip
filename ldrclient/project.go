package ldrclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/apology-is-policy/yip/ldrcore"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

var (
	ErrNoAuthority  = errors.New("ldrclient: verified store defines no such projection file")
	ErrNotProjected = errors.New("ldrclient: projection has not caught up to this file")
	ErrTainted      = errors.New("ldrclient: projection file disagrees with verified store")
)

type projCoord struct {
	gen uint64
	seq uint64
}

func (a projCoord) greater(b projCoord) bool {
	return a.gen > b.gen || (a.gen == b.gen && a.seq > b.seq)
}

type projFile struct {
	path    string
	content string
	view    bool
	tag     projCoord
}

func kvLines(kv ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		b.WriteString(kv[i] + "=" + kv[i+1] + "\n")
	}
	return b.String()
}

func ustr(n uint64) string { return fmt.Sprintf("%d", n) }
func istr(n int64) string  { return fmt.Sprintf("%d", n) }

func seqTag(gen, seq uint64) string {
	if gen > 1 {
		return fmt.Sprintf("g%d-s%d", gen, seq)
	}
	return ustr(seq)
}

func recordProjFiles(fr ldrrelay.ControlFrameWire, r ldrcore.Record, body string) []projFile {
	gen := max(fr.Gen, 1)
	head := []string{"type", r.Type, "seq", ustr(fr.Seq), "at", ustr(fr.SeqTime)}
	mkFile := func(p string, kv ...string) projFile {
		return projFile{path: p, content: kvLines(append(head, kv...)...)}
	}
	mkView := func(p string, kv ...string) projFile {
		all := append([]string{"derived_gen", ustr(gen), "derived_seq", ustr(fr.Seq)}, append(head, kv...)...)
		return projFile{path: p, content: kvLines(all...), view: true, tag: projCoord{gen: gen, seq: fr.Seq}}
	}
	call := "calls/" + r.Call + "/"
	st := seqTag(gen, fr.Seq)
	switch r.Type {
	case "call_open":
		return []projFile{
			mkFile(call+"call", "call", r.Call, "from", r.Actor, "to", r.To),
			mkFile(call+"turn-1", "call", r.Call, "from", r.Actor, "turn", "1", "barge", "false", "body", body),
		}
	case "call_turn":
		n := int64(0)
		if r.Expect.TurnCount != nil {
			n = *r.Expect.TurnCount + 1
		}
		return []projFile{mkFile(call+"turn-"+istr(n), "call", r.Call, "from", r.Actor, "turn", istr(n), "barge", fmt.Sprint(r.Barge), "body", body)}
	case "call_note":
		return []projFile{mkFile(call+"note-"+st, "call", r.Call, "from", r.Actor, "body", body)}
	case "call_ratify":
		return []projFile{mkFile(call+"ratify-"+st, "call", r.Call, "operator", r.Operator, "body", body)}
	case "call_attach":
		return []projFile{mkFile(call+"attach-"+st, "call", r.Call, "from", r.Actor, "body", body)}
	case "call_status":
		return []projFile{mkFile(call+"status-"+st, "call", r.Call, "from", r.Actor, "state", r.State, "related", r.Related, "reason", body)}
	case "dispute_open":
		return []projFile{mkFile(call+"dispute-opened-"+st, "call", r.Call, "from", r.Actor, "claim", body)}
	case "dispute_measure":
		return []projFile{mkView(call+"dispute-"+r.Dispute+"/measure-"+r.Actor, "call", r.Call, "from", r.Actor, "measurement", body)}
	case "dispute_resolve":
		return []projFile{mkView(call+"dispute-"+r.Dispute+"/resolution", "call", r.Call, "by", r.Actor, "kind", r.Kind, "detail", body)}
	case "dispute_arbitrate":
		return []projFile{mkView(call+"dispute-"+r.Dispute+"/resolution", "call", r.Call, "by", "operator:"+r.Operator, "kind", "human", "detail", body)}
	case "broadcast_create":
		return []projFile{mkFile("broadcasts/"+r.Broadcast+"/broadcast", "broadcast", r.Broadcast, "kind", r.Kind, "recipients", strings.Join(r.Recipients, ","), "default_audience", fmt.Sprint(r.DefaultAudience), "body", body)}
	case "broadcast_reply":
		return []projFile{mkFile("broadcasts/"+r.Broadcast+"/reply-"+st, "broadcast", r.Broadcast, "from", r.Actor, "body", body)}
	case "actor_declare":
		return []projFile{mkFile("actors/"+r.Actor+"/declared", "actor", r.Actor, "namespace", r.Namespace, "cred", r.Cred, "label", body)}
	}
	return nil
}

func projViewPath(obj string) string {
	kind, id, _ := strings.Cut(obj, ":")
	return kind + "s/" + id + "/view"
}

func diffTouchedObjects(before, after ldrcore.State) []string {
	var out []string
	for id, v := range after.Calls {
		if b := before.Calls[id]; b == nil || !reflect.DeepEqual(b, v) {
			out = append(out, "call:"+id)
		}
	}
	for id, v := range after.Broadcasts {
		if b := before.Broadcasts[id]; b == nil || !reflect.DeepEqual(b, v) {
			out = append(out, "broadcast:"+id)
		}
	}
	for id, v := range after.Line.Actors {
		if b := before.Line.Actors[id]; b == nil || !reflect.DeepEqual(b, v) {
			out = append(out, "actor:"+id)
		}
	}
	sort.Strings(out)
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func (c *Client) objectProjViewLocked(obj string) (projFile, bool) {
	kind, id, _ := strings.Cut(obj, ":")
	tag := c.touched[obj]
	kv := []string{"derived_gen", ustr(tag.gen), "derived_seq", ustr(tag.seq)}
	switch kind {
	case "call":
		v := c.state.Calls[id]
		if v == nil {
			return projFile{}, false
		}
		kv = append(kv, "call", id, "call_no", istr(v.CallNo), "from", v.From, "to", v.To,
			"turn_count", istr(v.TurnCount), "last_turn_from", v.LastTurnFrom, "floor", v.Floor(),
			"lifecycle", v.Lifecycle, "lifecycle_rev", istr(v.LifecycleRev), "status", v.Status(),
			"byes", strings.Join(sortedCopy(v.Byes), ","), "links", strings.Join(sortedCopy(v.Links), ","),
			"note_count", istr(v.NoteCount), "attach_count", istr(v.AttachCount), "dispute_count", istr(v.DisputeCount))
	case "broadcast":
		v := c.state.Broadcasts[id]
		if v == nil {
			return projFile{}, false
		}
		kv = append(kv, "broadcast", id)
		for _, a := range sortedCopy(v.Recipients) {
			read := "pending"
			if rc, ok := v.Receipts[a]; ok {
				read = fmt.Sprintf("g%d-s%d", rc.ReadGen, rc.ReadSeq)
			}
			kv = append(kv, "receipt."+a, read, "replies."+a, istr(v.ReplyCount[a]))
		}
	case "actor":
		v := c.state.Line.Actors[id]
		if v == nil {
			return projFile{}, false
		}
		kv = append(kv, "actor", id, "namespace", v.Namespace, "cred", v.Cred,
			"binding_gen", istr(v.BindingGen), "addr_rev", istr(v.AddrRev),
			"default_addressed", fmt.Sprint(v.DefaultAddressed), "live", fmt.Sprint(v.Live))
	default:
		return projFile{}, false
	}
	return projFile{path: projViewPath(obj), content: kvLines(kv...), view: true, tag: tag}, true
}

func parseProjViewTag(content string) (projCoord, bool) {
	first, rest, ok := strings.Cut(content, "\n")
	if !ok {
		return projCoord{}, false
	}
	second, _, _ := strings.Cut(rest, "\n")
	var g, s uint64
	if _, err := fmt.Sscanf(first, "derived_gen=%d", &g); err != nil || first != "derived_gen="+ustr(g) || g < 1 {
		return projCoord{}, false
	}
	if _, err := fmt.Sscanf(second, "derived_seq=%d", &s); err != nil || second != "derived_seq="+ustr(s) || s < 1 {
		return projCoord{}, false
	}
	return projCoord{gen: g, seq: s}, true
}

func (c *Client) syncProjDirChainLocked(startDir string) error {
	syncDir := c.syncDirFn
	if syncDir == nil {
		syncDir = ldrstore.SyncDir
	}
	projRoot := filepath.Clean(c.projDir())
	cur := filepath.Clean(startDir)
	for {
		if err := syncDir(cur); err != nil {
			return fmt.Errorf("%w: projection dir barrier sync %s: %v", ldrstore.ErrUncertainWrite, cur, err)
		}
		if cur == projRoot {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return nil
}

func (c *Client) syncProjAncestorDirsLocked(full string) error {
	projRoot := filepath.Clean(c.projDir())
	dir := filepath.Clean(filepath.Dir(full))
	if dir == projRoot {
		return nil
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return nil
	}
	return c.syncProjDirChainLocked(parent)
}

func (c *Client) syncProjPathBarrierLocked(full string) error {
	syncFile := c.syncFileFn
	if syncFile == nil {
		syncFile = ldrstore.SyncFile
	}
	f, err := os.OpenFile(full, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("%w: open projection file for barrier: %v", ldrstore.ErrUncertainWrite, err)
	}
	if err := syncFile(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("%w: projection file barrier sync: %v", ldrstore.ErrUncertainWrite, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%w: projection file close: %v", ldrstore.ErrUncertainWrite, err)
	}
	return c.syncProjDirChainLocked(filepath.Dir(full))
}

func (c *Client) writeProjFileLocked(pf projFile) (bool, error) {
	full := filepath.Join(c.projDir(), filepath.FromSlash(pf.path))
	oldBytes, err := os.ReadFile(full)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, err
		}
		if err := atomicWriteFileWithHooks(full, []byte(pf.content), 0o600, c.syncFileFn, c.syncDirFn); err != nil {
			return false, err
		}
		if err := c.syncProjAncestorDirsLocked(full); err != nil {
			return false, err
		}
		return true, nil
	}
	old := string(oldBytes)
	if !pf.view {
		if old != pf.content {
			return false, nil
		}
		// Ensure an already-visible matching projection file and its parent
		// directory chain are durably synced before advancing ProjectedSeq
		// (handles retry and reopen after a prior post-rename dir-sync failure).
		if err := c.syncProjPathBarrierLocked(full); err != nil {
			return false, err
		}
		return true, nil
	}
	tag, ok := parseProjViewTag(old)
	head := projCoord{gen: c.ckGen, seq: c.ckSeq}
	switch {
	case !ok || tag.greater(head):
		return false, nil
	case tag.greater(pf.tag):
		if err := c.syncProjPathBarrierLocked(full); err != nil {
			return false, err
		}
		return true, nil
	case tag == pf.tag:
		if old != pf.content {
			return false, nil
		}
		if err := c.syncProjPathBarrierLocked(full); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := atomicWriteFileWithHooks(full, []byte(pf.content), 0o600, c.syncFileFn, c.syncDirFn); err != nil {
		return false, err
	}
	if err := c.syncProjAncestorDirsLocked(full); err != nil {
		return false, err
	}
	return true, nil
}

// Project advances the rebuildable projection directory to ckSeq (separate
// durable cursor ProjectedSeq, §11.2 rules 2–3). Enforces the O25 activation
// and durability gates before publishing any file or advancing ProjectedSeq.
// ProjectedSeq is persisted via a staged candidate BEFORE publishing in memory
// so definite pre-write failures are retried on the next call and ambiguous
// writes fence cursor reliance until ReconcileDurability succeeds.
// If any file on disk disagrees with the verified store (e.g., local edit/taint),
// automatically wipes and rebuilds from verified.wal once.
func (c *Client) Project(ctx context.Context, sess *ldrrelay.SessionClient) error {
	rebuilt := false
	for {
		c.mu.Lock()
		if c.outboxUncertain {
			c.mu.Unlock()
			return ErrOutboxUncertain
		}
		if c.epochsUncertain {
			c.mu.Unlock()
			return ErrEpochsUncertain
		}
		if c.cursorsUncertain {
			c.mu.Unlock()
			return ErrCursorsUncertain
		}
		if !c.outbox.Activated {
			c.mu.Unlock()
			return ErrNotActivated
		}
		if c.cursors.WipePending {
			if err := c.completeWipeLocked(); err != nil {
				c.mu.Unlock()
				return err
			}
		}
		if c.cursors.ProjectedSeq >= c.ckSeq {
			c.mu.Unlock()
			return nil
		}
		seq := c.cursors.ProjectedSeq + 1
		ve := c.entries[seq-1]
		c.mu.Unlock()

		bodyStr := ldrcore.ReadNone
		if ve.decoded != nil && ve.decoded.PayloadCommit.Length > 0 {
			pt, rs, err := c.ReadPayload(ctx, sess, seq)
			if err != nil {
				return err
			}
			if rs == ldrcore.ReadOK {
				bodyStr = fmt.Sprintf("%s:%s", rs, hex.EncodeToString(sha256Sum(pt)))
			} else {
				bodyStr = rs
			}
		}

		c.mu.Lock()
		if c.outboxUncertain {
			c.mu.Unlock()
			return ErrOutboxUncertain
		}
		if c.epochsUncertain {
			c.mu.Unlock()
			return ErrEpochsUncertain
		}
		if c.cursorsUncertain {
			c.mu.Unlock()
			return ErrCursorsUncertain
		}
		if !c.outbox.Activated {
			c.mu.Unlock()
			return ErrNotActivated
		}
		if c.cursors.WipePending || c.cursors.ProjectedSeq != seq-1 {
			c.mu.Unlock()
			continue
		}
		var files []projFile
		if ve.decoded != nil {
			files = append(files, recordProjFiles(ve.frame, ve.decoded.Record, bodyStr)...)
		}
		for _, obj := range ve.touched {
			if vf, ok := c.objectProjViewLocked(obj); ok {
				files = append(files, vf)
			}
		}
		tainted := false
		for _, pf := range files {
			ok, err := c.writeProjFileLocked(pf)
			if err != nil {
				c.mu.Unlock()
				return err
			}
			if !ok {
				tainted = true
				break
			}
		}
		if tainted {
			if rebuilt {
				c.mu.Unlock()
				return fmt.Errorf("%w: projection disagreed at seq %d after rebuild", ErrTainted, seq)
			}
			rebuilt = true
			if err := c.wipeProjectionLocked(); err != nil {
				c.mu.Unlock()
				return err
			}
			c.mu.Unlock()
			continue
		}
		cand := clonePersistedCursors(c.cursors)
		cand.ProjectedSeq = seq
		if err := c.persistCursorsLocked(cand); err != nil {
			c.markCursorsUncertainOnErrLocked(err)
			c.mu.Unlock()
			return err
		}
		c.cursors = cand
		c.mu.Unlock()
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// Rebuild wipes the projection directory and re-materializes it cleanly from verified.wal.
func (c *Client) Rebuild(ctx context.Context, sess *ldrrelay.SessionClient) error {
	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return ErrOutboxUncertain
	}
	if c.epochsUncertain {
		c.mu.Unlock()
		return ErrEpochsUncertain
	}
	if c.cursorsUncertain {
		c.mu.Unlock()
		return ErrCursorsUncertain
	}
	if !c.outbox.Activated {
		c.mu.Unlock()
		return ErrNotActivated
	}
	if err := c.wipeProjectionLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	return c.Project(ctx, sess)
}

func (c *Client) wipeProjectionLocked() error {
	if !c.cursors.WipePending || c.cursors.ProjectedSeq != 0 {
		cand := clonePersistedCursors(c.cursors)
		cand.ProjectedSeq = 0
		if !c.cursors.WipePending {
			cand.Rebuilds++
		}
		cand.WipePending = true
		if err := c.persistCursorsLocked(cand); err != nil {
			c.markCursorsUncertainOnErrLocked(err)
			return err
		}
		c.cursors = cand
	}
	return c.completeWipeLocked()
}

func (c *Client) completeWipeLocked() error {
	projDir := c.projDir()
	if err := os.RemoveAll(projDir); err != nil {
		return fmt.Errorf("ldrclient: wipe projection directory failed: %w", err)
	}
	if _, err := os.Stat(projDir); err == nil {
		return fmt.Errorf("ldrclient: projection directory still exists after wipe: %s", projDir)
	} else if !os.IsNotExist(err) {
		return err
	}
	syncDir := c.syncDirFn
	if syncDir == nil {
		syncDir = ldrstore.SyncDir
	}
	if err := syncDir(c.dir); err != nil {
		return fmt.Errorf("%w: sync client dir after projection wipe: %v", ldrstore.ErrUncertainWrite, err)
	}
	if err := os.Mkdir(projDir, 0o700); err != nil {
		return err
	}
	if err := syncDir(projDir); err != nil {
		return fmt.Errorf("%w: sync recreated projection dir: %v", ldrstore.ErrUncertainWrite, err)
	}
	if err := syncDir(c.dir); err != nil {
		return fmt.Errorf("%w: sync client dir after recreating projection dir: %v", ldrstore.ErrUncertainWrite, err)
	}
	cand := clonePersistedCursors(c.cursors)
	cand.WipePending = false
	if err := c.persistCursorsLocked(cand); err != nil {
		c.markCursorsUncertainOnErrLocked(err)
		return err
	}
	c.cursors = cand
	return nil
}

// VerifiedRead reads a projected file ONLY after checking it against the
// authoritative verified store (§11.1). Local edits never acquire authority.
func (c *Client) VerifiedRead(ctx context.Context, sess *ldrrelay.SessionClient, relPath string) (string, error) {
	c.mu.Lock()
	if c.outboxUncertain {
		c.mu.Unlock()
		return "", ErrOutboxUncertain
	}
	if c.epochsUncertain {
		c.mu.Unlock()
		return "", ErrEpochsUncertain
	}
	if c.cursorsUncertain {
		c.mu.Unlock()
		return "", ErrCursorsUncertain
	}
	if !c.outbox.Activated {
		c.mu.Unlock()
		return "", ErrNotActivated
	}
	if c.cursors.WipePending {
		c.mu.Unlock()
		return "", ErrNotProjected
	}
	obj, isView := c.viewOf[relPath]
	coord, isRec := c.source[relPath]
	if !isView && !isRec {
		c.mu.Unlock()
		return "", ErrNoAuthority
	}
	var want string
	if isView {
		vf, ok := c.objectProjViewLocked(obj)
		if !ok {
			c.mu.Unlock()
			return "", ErrNoAuthority
		}
		want = vf.content
		if c.cursors.ProjectedSeq < vf.tag.seq {
			c.mu.Unlock()
			return "", ErrNotProjected
		}
	} else {
		if c.cursors.ProjectedSeq < coord.seq {
			c.mu.Unlock()
			return "", ErrNotProjected
		}
	}
	c.mu.Unlock()

	if !isView {
		c.mu.Lock()
		ve := c.entries[coord.seq-1]
		c.mu.Unlock()
		bodyStr := ldrcore.ReadNone
		if ve.decoded != nil && ve.decoded.PayloadCommit.Length > 0 {
			pt, rs, err := c.ReadPayload(ctx, sess, coord.seq)
			if err != nil {
				return "", err
			}
			if rs == ldrcore.ReadOK {
				bodyStr = fmt.Sprintf("%s:%s", rs, hex.EncodeToString(sha256Sum(pt)))
			} else {
				bodyStr = rs
			}
		}
		for _, pf := range recordProjFiles(ve.frame, ve.decoded.Record, bodyStr) {
			if pf.path == relPath {
				want = pf.content
				break
			}
		}
	}
	full := filepath.Join(c.projDir(), filepath.FromSlash(relPath))
	gotBytes, err := os.ReadFile(full)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrNotProjected
		}
		return "", err
	}
	if string(gotBytes) != want {
		return "", ErrTainted
	}
	return string(gotBytes), nil
}

// --- Local Delivery Scan Cursor (§11.3 & C2 Withholding) ---

func (c *Client) deriveOwedNoticesLocked(after *ldrcore.State, fr ldrrelay.ControlFrameWire, dec *ldrrelay.DecodedIntent) []LocalNotice {
	if c.credKeys == nil {
		return nil
	}
	myTok := ldrrelay.CredToken(c.credKeys.CredID)
	r := dec.Record
	var actors []string
	var kind, target string
	switch r.Type {
	case "call_open":
		actors = []string{r.To}
		kind, target = "call_open", r.Call
	case "call_turn", "call_bye", "call_note", "call_status", "call_attach", "dispute_open", "dispute_measure", "dispute_resolve":
		if cl := after.Calls[r.Call]; cl != nil {
			peer := cl.From
			if peer == r.Actor {
				peer = cl.To
			}
			actors = []string{peer}
			kind, target = r.Type, r.Call
		}
	case "call_ratify", "dispute_arbitrate":
		if cl := after.Calls[r.Call]; cl != nil {
			actors = []string{cl.From, cl.To}
			kind, target = r.Type, r.Call
		}
	case "broadcast_create":
		actors = sortedCopy(r.Recipients)
		kind, target = "broadcast", r.Broadcast
	}
	var out []LocalNotice
	for _, aID := range actors {
		a := after.Line.Actors[aID]
		if a == nil || !a.Live || a.Cred != myTok {
			continue
		}
		id := fmt.Sprintf("g%d-s%d-%s-%s", fr.Gen, fr.Seq, aID, kind)
		out = append(out, LocalNotice{
			ID:         id,
			Gen:        fr.Gen,
			Seq:        fr.Seq,
			Actor:      aID,
			BindingGen: uint64(a.BindingGen),
			Kind:       kind,
			Target:     target,
		})
	}
	return out
}

// ScanDelivery advances the durable ScannedSeq cursor over verified.wal and
// queues newly owed local notices (§11.3). Stages notice insertions and
// ScannedSeq in a candidate persisted BEFORE publishing in memory; refuses
// before O25 activation or while outbox/cursor durability is uncertain.
func (c *Client) ScanDelivery() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outboxUncertain {
		return 0, ErrOutboxUncertain
	}
	if c.cursorsUncertain {
		return 0, ErrCursorsUncertain
	}
	if !c.outbox.Activated {
		return 0, ErrNotActivated
	}
	if c.cursors.ScannedSeq >= c.ckSeq {
		return 0, nil
	}
	cand := clonePersistedCursors(c.cursors)
	added := 0
	for cand.ScannedSeq < c.ckSeq {
		seq := cand.ScannedSeq + 1
		ve := c.entries[seq-1]
		for _, n := range ve.owed {
			if _, exists := cand.Notices[n.ID]; !exists {
				nc := n
				cand.Notices[n.ID] = &nc
				added++
			}
		}
		cand.ScannedSeq = seq
	}
	if err := c.persistCursorsLocked(cand); err != nil {
		c.markCursorsUncertainOnErrLocked(err)
		return 0, err
	}
	c.cursors = cand
	return added, nil
}

// DeliverableNotices returns only unacknowledged notices whose actor is STILL
// live, bound to this credential, at the exact binding generation, and in the
// current generation (§11.3 / C2). Never exposes notices before O25 activation
// or while outbox/cursor durability is uncertain.
func (c *Client) DeliverableNotices() []LocalNotice {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outboxUncertain || c.cursorsUncertain || !c.outbox.Activated || c.credKeys == nil {
		return nil
	}
	myTok := ldrrelay.CredToken(c.credKeys.CredID)
	var out []LocalNotice
	for _, n := range c.cursors.Notices {
		if n.Acked || n.Gen != c.ckGen {
			continue
		}
		a := c.state.Line.Actors[n.Actor]
		if a == nil || !a.Live || a.Cred != myTok || uint64(a.BindingGen) != n.BindingGen {
			continue
		}
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// AckNotice durably marks a local notice acknowledged before publishing Acked
// in memory. Refuses while outbox/cursor durability is uncertain.
func (c *Client) AckNotice(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outboxUncertain {
		return ErrOutboxUncertain
	}
	if c.cursorsUncertain {
		return ErrCursorsUncertain
	}
	if !c.outbox.Activated {
		return ErrNotActivated
	}
	n, ok := c.cursors.Notices[id]
	if !ok {
		return fmt.Errorf("ldrclient: unknown notice %q", id)
	}
	if n.Acked {
		return nil
	}
	cand := clonePersistedCursors(c.cursors)
	cand.Notices[id].Acked = true
	if err := c.persistCursorsLocked(cand); err != nil {
		c.markCursorsUncertainOnErrLocked(err)
		return err
	}
	c.cursors = cand
	return nil
}

// Rebuilds returns how many times the projection was wiped and rebuilt.
func (c *Client) Rebuilds() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cursors.Rebuilds
}

// ProjectionDir returns the path to the rebuildable projection directory.
func (c *Client) ProjectionDir() string {
	return c.projDir()
}

// HasEpochKey reports whether this client durably holds the symmetric key for epoch.
func (c *Client) HasEpochKey(epoch uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.epochsUncertain {
		return false
	}
	_, ok := c.epochs.Keys[epoch]
	return ok
}

// CheckHostLocalResourcesUntouched is a sanity helper confirming no resource
// lease/queue directory exists inside the client projection directory (§11.4).
func (c *Client) CheckHostLocalResourcesUntouched() error {
	for _, forbidden := range []string{"resources", "leases", "queues"} {
		if _, err := os.Stat(filepath.Join(c.projDir(), forbidden)); err == nil {
			return fmt.Errorf("ldrclient: forbidden resource directory %q found in projection", forbidden)
		}
	}
	return nil
}

// Unused import check guard: ensure slices stays referenced cleanly.
var _ = slices.Contains[[]string, string]
