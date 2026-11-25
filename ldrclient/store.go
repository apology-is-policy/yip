package ldrclient

import (
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"

	"github.com/apology-is-policy/yip/ldrcrypto"
	"github.com/apology-is-policy/yip/ldrrelay"
	"github.com/apology-is-policy/yip/ldrstore"
)

func p256Curve() elliptic.Curve { return elliptic.P256() }

const (
	clientWALMagic   = "LDCW"
	clientWALVersion = byte(1)
	clientWALHdrSize = 10 // 4B magic + 1B ver + 1B flags + 4B len
	clientWALCRCSize = 4
	clientWALMaxBody = 1024 * 1024
)

var clientCRCTable = crc32.MakeTable(crc32.Castagnoli)

// OutboxEntry is a durably persisted intent stored strictly BEFORE first send.
type OutboxEntry struct {
	OpID           string
	Action         string
	Slot           string
	Gen            uint64
	SignerToken    string
	Principal      ldrcrypto.Principal
	SeenSeq        uint64
	SeenHead       [32]byte
	OpType         string
	IntentBytes    []byte
	IntentDigest   [32]byte
	PayloadSidecar []byte
	WrapSidecars   map[[32]byte][]byte
	Status         string // pending | done | closed | reconciliation_required
	Sends          uint64
	LastClass      string
	LastCode       string
	OutcomeKind    string
	OutcomeReason  string
	OutcomeSeq     uint64
}

// KeyStop is a persistent Rule 8 record of a stopped/revoked local key.
type KeyStop struct {
	Key      string
	Told     bool
	Verified bool
	Seq      uint64
	Head     [32]byte
	Code     string
}

type persistedOutbox struct {
	NextOp      uint64
	MustResolve bool
	Suspect     bool
	Halted      string
	Activated   bool
	KeyStops    map[string]*KeyStop
	Entries     []*OutboxEntry
}

// LocalNotice is a delivery notice derived from verified log records (§11.3).
type LocalNotice struct {
	ID         string
	Gen        uint64
	Seq        uint64
	Actor      string
	BindingGen uint64
	Kind       string
	Target     string
	Acked      bool
}

type persistedCursors struct {
	ProjectedSeq uint64
	ScannedSeq   uint64
	Rebuilds     uint64
	Notices      map[string]*LocalNotice
}

type persistedConfig struct {
	SignedDescriptor  []byte
	LineID            []byte
	DescriptorDigest  [32]byte
	GenesisAnchor     [32]byte
	ExpectedCredID    *[32]byte
	ExpectedGrant     *ldrcrypto.JoinGrant
	ExpectedJoinReqID []byte
}

type persistedEpochs struct {
	Keys     map[uint64][]byte
	BadWraps map[uint64]bool
}

func (c *Client) configPath() string  { return filepath.Join(c.dir, "config.cbor") }
func (c *Client) walPath() string     { return filepath.Join(c.dir, "verified.wal") }
func (c *Client) outboxPath() string  { return filepath.Join(c.dir, "outbox.cbor") }
func (c *Client) epochsPath() string  { return filepath.Join(c.dir, "epochs.cbor") }
func (c *Client) cursorsPath() string { return filepath.Join(c.dir, "cursors.cbor") }
func (c *Client) projDir() string     { return filepath.Join(c.dir, "projection") }
func (c *Client) sidecarsDir() string { return filepath.Join(c.dir, "sidecars") }
func (c *Client) credKeyPath() string { return filepath.Join(c.dir, "cred.key") }

func (c *Client) sidecarCachePath(kind string, digest [32]byte) string {
	return filepath.Join(c.sidecarsDir(), kind+"-"+hex.EncodeToString(digest[:]))
}

func saveConfig(path string, cfg persistedConfig) error {
	m := ldrcrypto.Map{
		{Key: "cd", Value: cfg.DescriptorDigest[:]},
		{Key: "descriptor", Value: cfg.SignedDescriptor},
		{Key: "genesis", Value: cfg.GenesisAnchor[:]},
		{Key: "line_id", Value: cfg.LineID},
		{Key: "v", Value: uint64(1)},
	}
	if cfg.ExpectedCredID != nil {
		m = append(m, ldrcrypto.MapEntry{Key: "expected_cred_id", Value: cfg.ExpectedCredID[:]})
	}
	if cfg.ExpectedGrant != nil {
		caps := append([]string(nil), cfg.ExpectedGrant.Capabilities...)
		if caps == nil {
			caps = []string{}
		}
		m = append(m, ldrcrypto.MapEntry{
			Key: "expected_grant",
			Value: ldrcrypto.Map{
				{Key: "actor_limit", Value: cfg.ExpectedGrant.ActorLimit},
				{Key: "capabilities", Value: caps},
				{Key: "namespace_id", Value: cfg.ExpectedGrant.NamespaceID},
				{Key: "reader", Value: cfg.ExpectedGrant.Reader},
			},
		})
	}
	if len(cfg.ExpectedJoinReqID) > 0 {
		m = append(m, ldrcrypto.MapEntry{Key: "expected_join_req_id", Value: cfg.ExpectedJoinReqID})
	}
	raw, err := ldrcrypto.MarshalCBOR(m)
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

func loadConfig(path string) (persistedConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return persistedConfig{}, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return persistedConfig{}, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return persistedConfig{}, errors.New("ldrclient: invalid config.cbor")
	}
	if err := ldrcrypto.RequireExactKeys(m, []string{"cd", "descriptor", "genesis", "line_id", "v"},
		"expected_cred_id", "expected_grant", "expected_join_req_id"); err != nil {
		return persistedConfig{}, err
	}
	var cfg persistedConfig
	var err2 error
	if cfg.SignedDescriptor, err2 = ldrcrypto.MapBytes(m, "descriptor"); err2 != nil {
		return persistedConfig{}, err2
	}
	if cfg.LineID, err2 = ldrcrypto.MapBytes(m, "line_id"); err2 != nil {
		return persistedConfig{}, err2
	}
	cdB, err := ldrcrypto.MapBytesLen(m, "cd", 32)
	if err != nil {
		return persistedConfig{}, err
	}
	genB, err := ldrcrypto.MapBytesLen(m, "genesis", 32)
	if err != nil {
		return persistedConfig{}, err
	}
	copy(cfg.DescriptorDigest[:], cdB)
	copy(cfg.GenesisAnchor[:], genB)
	if _, has := m["expected_cred_id"]; has {
		cb, err := ldrcrypto.MapBytesLen(m, "expected_cred_id", 32)
		if err != nil {
			return persistedConfig{}, err
		}
		var id [32]byte
		copy(id[:], cb)
		cfg.ExpectedCredID = &id
	}
	if _, has := m["expected_grant"]; has {
		gm, err := ldrcrypto.MapSubmap(m, "expected_grant")
		if err != nil {
			return persistedConfig{}, err
		}
		ns, err1 := ldrcrypto.MapString(gm, "namespace_id")
		al, err2 := ldrcrypto.MapUint(gm, "actor_limit")
		rd, err3 := ldrcrypto.MapBool(gm, "reader")
		ca, err4 := ldrcrypto.MapArray(gm, "capabilities")
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			return persistedConfig{}, errors.New("ldrclient: malformed expected_grant")
		}
		caps := make([]string, len(ca))
		for i, x := range ca {
			s, ok := x.(string)
			if !ok {
				return persistedConfig{}, errors.New("ldrclient: malformed expected_grant capabilities")
			}
			caps[i] = s
		}
		cfg.ExpectedGrant = &ldrcrypto.JoinGrant{NamespaceID: ns, ActorLimit: al, Reader: rd, Capabilities: caps}
	}
	if _, has := m["expected_join_req_id"]; has {
		if cfg.ExpectedJoinReqID, err = ldrcrypto.MapBytes(m, "expected_join_req_id"); err != nil {
			return persistedConfig{}, err
		}
	}
	return cfg, nil
}

func appendVerifiedFrameWAL(path string, fr ldrrelay.ControlFrameWire) error {
	ib := fr.IntentBytes
	if ib == nil {
		ib = []byte{}
	}
	body, err := ldrcrypto.MarshalCBORWithLimits(ldrcrypto.Map{
		{Key: "gen", Value: fr.Gen},
		{Key: "head", Value: fr.Head[:]},
		{Key: "intent", Value: ib},
		{Key: "op_type", Value: fr.OpType},
		{Key: "origin", Value: fr.Origin},
		{Key: "prev_head", Value: fr.PrevHead[:]},
		{Key: "seq", Value: fr.Seq},
		{Key: "seq_time", Value: fr.SeqTime},
		{Key: "v", Value: uint64(1)},
	}, ldrcrypto.Limits{MaxBytes: clientWALMaxBody, MaxDepth: 16, MaxItems: 8192})
	if err != nil {
		return err
	}
	buf := make([]byte, clientWALHdrSize+len(body)+clientWALCRCSize)
	copy(buf[0:4], clientWALMagic)
	buf[4] = clientWALVersion
	buf[5] = 0
	binary.BigEndian.PutUint32(buf[6:10], uint32(len(body)))
	copy(buf[10:10+len(body)], body)
	crc := crc32.Checksum(buf[:10+len(body)], clientCRCTable)
	binary.BigEndian.PutUint32(buf[10+len(body):], crc)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		_ = f.Close()
		return err
	}
	if err := ldrstore.SyncFile(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func loadVerifiedWAL(path string) ([]ldrrelay.ControlFrameWire, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []ldrrelay.ControlFrameWire
	off := 0
	for off < len(data) {
		rem := len(data) - off
		if rem < clientWALHdrSize {
			// Truncated tail at EOF: safely truncate.
			if err := truncateClientWAL(path, int64(off)); err != nil {
				return nil, err
			}
			break
		}
		hdr := data[off : off+clientWALHdrSize]
		if string(hdr[0:4]) != clientWALMagic || hdr[4] != clientWALVersion || hdr[5] != 0 {
			return nil, fmt.Errorf("ldrclient: corrupt verified.wal header at offset %d", off)
		}
		bodyLen := int(binary.BigEndian.Uint32(hdr[6:10]))
		if bodyLen == 0 || bodyLen > clientWALMaxBody {
			return nil, fmt.Errorf("ldrclient: invalid verified.wal body length %d", bodyLen)
		}
		frameLen := clientWALHdrSize + bodyLen + clientWALCRCSize
		if off+frameLen > len(data) {
			if err := truncateClientWAL(path, int64(off)); err != nil {
				return nil, err
			}
			break
		}
		fb := data[off : off+frameLen]
		wantCRC := binary.BigEndian.Uint32(fb[clientWALHdrSize+bodyLen:])
		if crc32.Checksum(fb[:clientWALHdrSize+bodyLen], clientCRCTable) != wantCRC {
			return nil, fmt.Errorf("ldrclient: verified.wal CRC32C mismatch at offset %d", off)
		}
		dec, err := ldrcrypto.UnmarshalCBOR(fb[clientWALHdrSize:clientWALHdrSize+bodyLen], ldrcrypto.Limits{MaxBytes: clientWALMaxBody, MaxDepth: 16, MaxItems: 8192})
		if err != nil {
			return nil, err
		}
		m, ok := dec.(map[string]any)
		if !ok {
			return nil, errors.New("ldrclient: invalid verified.wal frame body")
		}
		var fr ldrrelay.ControlFrameWire
		fr.Gen, _ = ldrcrypto.MapUint(m, "gen")
		fr.Seq, _ = ldrcrypto.MapUint(m, "seq")
		fr.SeqTime, _ = ldrcrypto.MapUint(m, "seq_time")
		fr.Origin, _ = ldrcrypto.MapString(m, "origin")
		fr.OpType, _ = ldrcrypto.MapString(m, "op_type")
		fr.IntentBytes, _ = ldrcrypto.MapBytes(m, "intent")
		ph, err1 := ldrcrypto.MapBytesLen(m, "prev_head", 32)
		hd, err2 := ldrcrypto.MapBytesLen(m, "head", 32)
		if err1 != nil || err2 != nil {
			return nil, errors.New("ldrclient: invalid verified.wal head bytes")
		}
		copy(fr.PrevHead[:], ph)
		copy(fr.Head[:], hd)
		out = append(out, fr)
		off += frameLen
	}
	return out, nil
}

func truncateClientWAL(path string, sz int64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := f.Truncate(sz); err != nil {
		_ = f.Close()
		return err
	}
	if err := ldrstore.SyncFile(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func saveOutbox(path string, ob persistedOutbox) error {
	stops := make([]any, 0, len(ob.KeyStops))
	stopKeys := make([]string, 0, len(ob.KeyStops))
	for k := range ob.KeyStops {
		stopKeys = append(stopKeys, k)
	}
	sort.Strings(stopKeys)
	for _, k := range stopKeys {
		ks := ob.KeyStops[k]
		stops = append(stops, ldrcrypto.Map{
			{Key: "code", Value: ks.Code},
			{Key: "head", Value: ks.Head[:]},
			{Key: "key", Value: ks.Key},
			{Key: "seq", Value: ks.Seq},
			{Key: "told", Value: ks.Told},
			{Key: "verified", Value: ks.Verified},
		})
	}
	entries := make([]any, 0, len(ob.Entries))
	for _, e := range ob.Entries {
		pCBOR, err := e.Principal.ToCBOR()
		if err != nil {
			return err
		}
		ps := e.PayloadSidecar
		if ps == nil {
			ps = []byte{}
		}
		wsArr := make([]any, 0, len(e.WrapSidecars))
		wIDs := make([][32]byte, 0, len(e.WrapSidecars))
		for id := range e.WrapSidecars {
			wIDs = append(wIDs, id)
		}
		sort.Slice(wIDs, func(i, j int) bool { return string(wIDs[i][:]) < string(wIDs[j][:]) })
		for _, id := range wIDs {
			wsArr = append(wsArr, ldrcrypto.Map{
				{Key: "cred_id", Value: append([]byte(nil), id[:]...)},
				{Key: "data", Value: e.WrapSidecars[id]},
			})
		}
		entries = append(entries, ldrcrypto.Map{
			{Key: "action", Value: e.Action},
			{Key: "gen", Value: e.Gen},
			{Key: "intent", Value: e.IntentBytes},
			{Key: "intent_digest", Value: e.IntentDigest[:]},
			{Key: "last_class", Value: e.LastClass},
			{Key: "last_code", Value: e.LastCode},
			{Key: "op_id", Value: e.OpID},
			{Key: "op_type", Value: e.OpType},
			{Key: "outcome_kind", Value: e.OutcomeKind},
			{Key: "outcome_reason", Value: e.OutcomeReason},
			{Key: "outcome_seq", Value: e.OutcomeSeq},
			{Key: "payload", Value: ps},
			{Key: "principal", Value: pCBOR},
			{Key: "seen_head", Value: e.SeenHead[:]},
			{Key: "seen_seq", Value: e.SeenSeq},
			{Key: "sends", Value: e.Sends},
			{Key: "signer", Value: e.SignerToken},
			{Key: "slot", Value: e.Slot},
			{Key: "status", Value: e.Status},
			{Key: "wraps", Value: wsArr},
		})
	}
	raw, err := ldrcrypto.MarshalCBORWithLimits(ldrcrypto.Map{
		{Key: "activated", Value: ob.Activated},
		{Key: "entries", Value: entries},
		{Key: "halted", Value: ob.Halted},
		{Key: "key_stops", Value: stops},
		{Key: "must_resolve", Value: ob.MustResolve},
		{Key: "next_op", Value: ob.NextOp},
		{Key: "suspect", Value: ob.Suspect},
		{Key: "v", Value: uint64(1)},
	}, ldrcrypto.Limits{MaxBytes: 4 * 1024 * 1024, MaxDepth: 16, MaxItems: 32768})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

func loadOutbox(path string) (persistedOutbox, error) {
	ob := persistedOutbox{KeyStops: make(map[string]*KeyStop)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ob, nil
		}
		return ob, err
	}
	dec, err := ldrcrypto.UnmarshalCBOR(raw, ldrcrypto.Limits{MaxBytes: 4 * 1024 * 1024, MaxDepth: 16, MaxItems: 32768})
	if err != nil {
		return ob, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return ob, errors.New("ldrclient: invalid outbox.cbor")
	}
	ob.Activated, _ = ldrcrypto.MapBool(m, "activated")
	ob.Halted, _ = ldrcrypto.MapString(m, "halted")
	ob.MustResolve, _ = ldrcrypto.MapBool(m, "must_resolve")
	ob.NextOp, _ = ldrcrypto.MapUint(m, "next_op")
	ob.Suspect, _ = ldrcrypto.MapBool(m, "suspect")

	if ksArr, err := ldrcrypto.MapArray(m, "key_stops"); err == nil {
		for _, elem := range ksArr {
			km, ok := elem.(map[string]any)
			if !ok {
				return ob, errors.New("ldrclient: invalid key_stop")
			}
			ks := &KeyStop{}
			ks.Key, _ = ldrcrypto.MapString(km, "key")
			ks.Code, _ = ldrcrypto.MapString(km, "code")
			ks.Seq, _ = ldrcrypto.MapUint(km, "seq")
			ks.Told, _ = ldrcrypto.MapBool(km, "told")
			ks.Verified, _ = ldrcrypto.MapBool(km, "verified")
			if hb, err := ldrcrypto.MapBytesLen(km, "head", 32); err == nil {
				copy(ks.Head[:], hb)
			}
			ob.KeyStops[ks.Key] = ks
		}
	}
	if entArr, err := ldrcrypto.MapArray(m, "entries"); err == nil {
		for _, elem := range entArr {
			em, ok := elem.(map[string]any)
			if !ok {
				return ob, errors.New("ldrclient: invalid outbox entry")
			}
			prin, err := ldrcrypto.ParsePrincipal(em["principal"])
			if err != nil {
				return ob, err
			}
			e := &OutboxEntry{Principal: prin, WrapSidecars: make(map[[32]byte][]byte)}
			e.OpID, _ = ldrcrypto.MapString(em, "op_id")
			e.Action, _ = ldrcrypto.MapString(em, "action")
			e.Slot, _ = ldrcrypto.MapString(em, "slot")
			e.Gen, _ = ldrcrypto.MapUint(em, "gen")
			e.SignerToken, _ = ldrcrypto.MapString(em, "signer")
			e.SeenSeq, _ = ldrcrypto.MapUint(em, "seen_seq")
			e.OpType, _ = ldrcrypto.MapString(em, "op_type")
			e.IntentBytes, _ = ldrcrypto.MapBytes(em, "intent")
			e.PayloadSidecar, _ = ldrcrypto.MapBytes(em, "payload")
			e.Status, _ = ldrcrypto.MapString(em, "status")
			e.Sends, _ = ldrcrypto.MapUint(em, "sends")
			e.LastClass, _ = ldrcrypto.MapString(em, "last_class")
			e.LastCode, _ = ldrcrypto.MapString(em, "last_code")
			e.OutcomeKind, _ = ldrcrypto.MapString(em, "outcome_kind")
			e.OutcomeReason, _ = ldrcrypto.MapString(em, "outcome_reason")
			e.OutcomeSeq, _ = ldrcrypto.MapUint(em, "outcome_seq")
			if sh, err := ldrcrypto.MapBytesLen(em, "seen_head", 32); err == nil {
				copy(e.SeenHead[:], sh)
			}
			if idg, err := ldrcrypto.MapBytesLen(em, "intent_digest", 32); err == nil {
				copy(e.IntentDigest[:], idg)
			}
			if wArr, err := ldrcrypto.MapArray(em, "wraps"); err == nil {
				for _, we := range wArr {
					wm, ok := we.(map[string]any)
					if !ok {
						continue
					}
					cidB, err1 := ldrcrypto.MapBytesLen(wm, "cred_id", 32)
					wb, err2 := ldrcrypto.MapBytes(wm, "data")
					if err1 == nil && err2 == nil {
						var cid [32]byte
						copy(cid[:], cidB)
						e.WrapSidecars[cid] = wb
					}
				}
			}
			ob.Entries = append(ob.Entries, e)
		}
	}
	return ob, nil
}

func saveEpochs(path string, ep persistedEpochs) error {
	keysArr := make([]any, 0, len(ep.Keys))
	ids := make([]uint64, 0, len(ep.Keys))
	for id := range ep.Keys {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		keysArr = append(keysArr, ldrcrypto.Map{
			{Key: "epoch", Value: id},
			{Key: "key", Value: ep.Keys[id]},
		})
	}
	badArr := make([]any, 0, len(ep.BadWraps))
	bIDs := make([]uint64, 0, len(ep.BadWraps))
	for id, bad := range ep.BadWraps {
		if bad {
			bIDs = append(bIDs, id)
		}
	}
	sort.Slice(bIDs, func(i, j int) bool { return bIDs[i] < bIDs[j] })
	for _, id := range bIDs {
		badArr = append(badArr, id)
	}
	raw, err := ldrcrypto.MarshalCBOR(ldrcrypto.Map{
		{Key: "bad_wraps", Value: badArr},
		{Key: "keys", Value: keysArr},
		{Key: "v", Value: uint64(1)},
	})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

func loadEpochs(path string) (persistedEpochs, error) {
	ep := persistedEpochs{Keys: make(map[uint64][]byte), BadWraps: make(map[uint64]bool)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ep, nil
		}
		return ep, err
	}
	dec, err := ldrcrypto.UnmarshalCBORDefault(raw)
	if err != nil {
		return ep, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return ep, errors.New("ldrclient: invalid epochs.cbor")
	}
	if arr, err := ldrcrypto.MapArray(m, "keys"); err == nil {
		for _, elem := range arr {
			km, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			id, err1 := ldrcrypto.MapUint(km, "epoch")
			kb, err2 := ldrcrypto.MapBytesLen(km, "key", ldrcrypto.EpochKeySize)
			if err1 == nil && err2 == nil {
				ep.Keys[id] = kb
			}
		}
	}
	if arr, err := ldrcrypto.MapArray(m, "bad_wraps"); err == nil {
		for _, elem := range arr {
			if id, ok := elem.(uint64); ok {
				ep.BadWraps[id] = true
			}
		}
	}
	return ep, nil
}

func saveCursors(path string, cur persistedCursors) error {
	nIDs := make([]string, 0, len(cur.Notices))
	for id := range cur.Notices {
		nIDs = append(nIDs, id)
	}
	sort.Strings(nIDs)
	nArr := make([]any, 0, len(nIDs))
	for _, id := range nIDs {
		n := cur.Notices[id]
		nArr = append(nArr, ldrcrypto.Map{
			{Key: "acked", Value: n.Acked},
			{Key: "actor", Value: n.Actor},
			{Key: "binding_gen", Value: n.BindingGen},
			{Key: "gen", Value: n.Gen},
			{Key: "id", Value: n.ID},
			{Key: "kind", Value: n.Kind},
			{Key: "seq", Value: n.Seq},
			{Key: "target", Value: n.Target},
		})
	}
	raw, err := ldrcrypto.MarshalCBORWithLimits(ldrcrypto.Map{
		{Key: "notices", Value: nArr},
		{Key: "projected_seq", Value: cur.ProjectedSeq},
		{Key: "rebuilds", Value: cur.Rebuilds},
		{Key: "scanned_seq", Value: cur.ScannedSeq},
		{Key: "v", Value: uint64(1)},
	}, ldrcrypto.Limits{MaxBytes: 2 * 1024 * 1024, MaxDepth: 16, MaxItems: 32768})
	if err != nil {
		return err
	}
	return ldrstore.AtomicWriteFile(path, raw, 0o600)
}

func loadCursors(path string) (persistedCursors, error) {
	cur := persistedCursors{Notices: make(map[string]*LocalNotice)}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cur, nil
		}
		return cur, err
	}
	dec, err := ldrcrypto.UnmarshalCBOR(raw, ldrcrypto.Limits{MaxBytes: 2 * 1024 * 1024, MaxDepth: 16, MaxItems: 32768})
	if err != nil {
		return cur, err
	}
	m, ok := dec.(map[string]any)
	if !ok {
		return cur, errors.New("ldrclient: invalid cursors.cbor")
	}
	cur.ProjectedSeq, _ = ldrcrypto.MapUint(m, "projected_seq")
	cur.ScannedSeq, _ = ldrcrypto.MapUint(m, "scanned_seq")
	cur.Rebuilds, _ = ldrcrypto.MapUint(m, "rebuilds")
	if arr, err := ldrcrypto.MapArray(m, "notices"); err == nil {
		for _, elem := range arr {
			nm, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			n := &LocalNotice{}
			n.ID, _ = ldrcrypto.MapString(nm, "id")
			n.Gen, _ = ldrcrypto.MapUint(nm, "gen")
			n.Seq, _ = ldrcrypto.MapUint(nm, "seq")
			n.Actor, _ = ldrcrypto.MapString(nm, "actor")
			n.BindingGen, _ = ldrcrypto.MapUint(nm, "binding_gen")
			n.Kind, _ = ldrcrypto.MapString(nm, "kind")
			n.Target, _ = ldrcrypto.MapString(nm, "target")
			n.Acked, _ = ldrcrypto.MapBool(nm, "acked")
			cur.Notices[n.ID] = n
		}
	}
	return cur, nil
}
