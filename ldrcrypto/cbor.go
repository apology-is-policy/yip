// Package ldrcrypto implements Profile v1 cryptographic primitives, strict
// deterministic CBOR encoding (RFC 8949 §4.2.1), domain-separated digests,
// canonical signatures (Ed25519 + strict low-S ECDSA P-256), RFC 9180 HPKE
// Base mode, payload AEAD, and canonical envelope builders for LDR.
//
// Zero third-party dependencies: 100% Go standard library.
package ldrcrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"unicode/utf8"
)

const (
	// MaxCounter is 2^53 - 1, matching ldrcore.MaxCounter (LDR-STATE-MACHINE §5.9).
	MaxCounter uint64 = (1 << 53) - 1

	// Default CBOR framing limits (conservative phase-1 bounds).
	DefaultMaxBytes = 512 * 1024
	DefaultMaxDepth = 16
	DefaultMaxItems = 4096
)

var (
	ErrCBORInvalid       = errors.New("ldrcrypto: invalid cbor")
	ErrCBORNonCanonical  = errors.New("ldrcrypto: non-canonical cbor")
	ErrCBORUnsupported   = errors.New("ldrcrypto: unsupported cbor type")
	ErrCBORLimitExceeded = errors.New("ldrcrypto: cbor limit exceeded")
	ErrCBORTrailingBytes = errors.New("ldrcrypto: trailing bytes after cbor item")
	ErrCBOROutOfDomain   = errors.New("ldrcrypto: integer exceeds safe domain [0, 2^53-1]")
)

// Limits bounds CBOR encoding and decoding before allocation.
type Limits struct {
	MaxBytes int
	MaxDepth int
	MaxItems int
}

// DefaultLimits returns conservative default CBOR bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes: DefaultMaxBytes,
		MaxDepth: DefaultMaxDepth,
		MaxItems: DefaultMaxItems,
	}
}

func (l Limits) normalized() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	if l.MaxItems <= 0 {
		l.MaxItems = DefaultMaxItems
	}
	return l
}

// MapEntry is an explicit key/value pair for deterministic CBOR maps.
type MapEntry struct {
	Key   string
	Value any
}

// Map encodes as a deterministic CBOR map sorted by RFC 8949 §4.2.1 encoded key bytes.
type Map []MapEntry

// MarshalCBOR encodes v into the LDR strict deterministic CBOR subset using DefaultLimits.
func MarshalCBOR(v any) ([]byte, error) {
	return MarshalCBORWithLimits(v, DefaultLimits())
}

// MarshalCBORWithLimits encodes v into the LDR strict deterministic CBOR subset.
func MarshalCBORWithLimits(v any, lim Limits) ([]byte, error) {
	lim = lim.normalized()
	enc := cborEncoder{lim: lim}
	if err := enc.encodeValue(v, 0); err != nil {
		return nil, err
	}
	if len(enc.buf) > lim.MaxBytes {
		return nil, fmt.Errorf("%w: encoded size %d > %d", ErrCBORLimitExceeded, len(enc.buf), lim.MaxBytes)
	}
	return enc.buf, nil
}

type cborEncoder struct {
	buf   []byte
	lim   Limits
	items int
}

func (e *cborEncoder) countItem() error {
	e.items++
	if e.items > e.lim.MaxItems {
		return fmt.Errorf("%w: item count > %d", ErrCBORLimitExceeded, e.lim.MaxItems)
	}
	return nil
}

func (e *cborEncoder) checkSize(extra int) error {
	if extra < 0 || extra > e.lim.MaxBytes-len(e.buf) {
		return fmt.Errorf("%w: encoded size > %d", ErrCBORLimitExceeded, e.lim.MaxBytes)
	}
	return nil
}

func typeArgLen(n uint64) int {
	switch {
	case n < 24:
		return 1
	case n <= 0xff:
		return 2
	case n <= 0xffff:
		return 3
	case n <= 0xffffffff:
		return 5
	default:
		return 9
	}
}

func appendTypeArg(dst []byte, major byte, n uint64) []byte {
	mt := major << 5
	switch {
	case n < 24:
		return append(dst, mt|byte(n))
	case n <= 0xff:
		return append(dst, mt|24, byte(n))
	case n <= 0xffff:
		var tmp [3]byte
		tmp[0] = mt | 25
		binary.BigEndian.PutUint16(tmp[1:], uint16(n))
		return append(dst, tmp[:]...)
	case n <= 0xffffffff:
		var tmp [5]byte
		tmp[0] = mt | 26
		binary.BigEndian.PutUint32(tmp[1:], uint32(n))
		return append(dst, tmp[:]...)
	default:
		var tmp [9]byte
		tmp[0] = mt | 27
		binary.BigEndian.PutUint64(tmp[1:], n)
		return append(dst, tmp[:]...)
	}
}

func isStrictASCIIKey(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func encodeASCIIKey(k string) ([]byte, error) {
	if !isStrictASCIIKey(k) {
		return nil, fmt.Errorf("%w: map key must be printable ASCII", ErrCBORUnsupported)
	}
	if uint64(len(k)) > MaxCounter {
		return nil, ErrCBOROutOfDomain
	}
	out := make([]byte, 0, typeArgLen(uint64(len(k)))+len(k))
	out = appendTypeArg(out, 3, uint64(len(k)))
	out = append(out, k...)
	return out, nil
}

func (e *cborEncoder) encodeUint(n uint64) error {
	if n > MaxCounter {
		return fmt.Errorf("%w: %d", ErrCBOROutOfDomain, n)
	}
	if err := e.checkSize(typeArgLen(n)); err != nil {
		return err
	}
	e.buf = appendTypeArg(e.buf, 0, n)
	return nil
}

func (e *cborEncoder) checkHeaderAndPayload(payloadLen int) error {
	if payloadLen < 0 || uint64(payloadLen) > MaxCounter {
		return ErrCBOROutOfDomain
	}
	hdr := typeArgLen(uint64(payloadLen))
	rem := e.lim.MaxBytes - len(e.buf)
	if hdr > rem || payloadLen > rem-hdr {
		return fmt.Errorf("%w: encoded size > %d", ErrCBORLimitExceeded, e.lim.MaxBytes)
	}
	return nil
}

func (e *cborEncoder) preflightArray(n int, depth int) error {
	if depth >= e.lim.MaxDepth {
		return fmt.Errorf("%w: depth > %d", ErrCBORLimitExceeded, e.lim.MaxDepth)
	}
	if n < 0 || uint64(n) > MaxCounter {
		return ErrCBOROutOfDomain
	}
	hdr := typeArgLen(uint64(n))
	if err := e.checkSize(hdr); err != nil {
		return err
	}
	remItems := e.lim.MaxItems - e.items
	remBytes := e.lim.MaxBytes - len(e.buf) - hdr
	// Every array element requires at least 1 item and at least 1 encoded byte.
	if n > remItems || n > remBytes {
		return fmt.Errorf("%w: array length %d exceeds remaining budget", ErrCBORLimitExceeded, n)
	}
	return nil
}

func (e *cborEncoder) encodeValue(v any, depth int) error {
	if err := e.countItem(); err != nil {
		return err
	}
	switch x := v.(type) {
	case uint64:
		return e.encodeUint(x)
	case uint:
		return e.encodeUint(uint64(x))
	case uint32:
		return e.encodeUint(uint64(x))
	case uint16:
		return e.encodeUint(uint64(x))
	case uint8:
		return e.encodeUint(uint64(x))
	case int:
		if x < 0 {
			return fmt.Errorf("%w: negative integer %d", ErrCBORUnsupported, x)
		}
		return e.encodeUint(uint64(x))
	case int64:
		if x < 0 {
			return fmt.Errorf("%w: negative integer %d", ErrCBORUnsupported, x)
		}
		return e.encodeUint(uint64(x))
	case bool:
		if err := e.checkSize(1); err != nil {
			return err
		}
		if x {
			e.buf = append(e.buf, 0xf5)
		} else {
			e.buf = append(e.buf, 0xf4)
		}
		return nil
	case []byte:
		if err := e.checkHeaderAndPayload(len(x)); err != nil {
			return err
		}
		e.buf = appendTypeArg(e.buf, 2, uint64(len(x)))
		e.buf = append(e.buf, x...)
		return nil
	case string:
		if err := e.checkHeaderAndPayload(len(x)); err != nil {
			return err
		}
		if !utf8.ValidString(x) {
			return fmt.Errorf("%w: invalid UTF-8 string", ErrCBORInvalid)
		}
		e.buf = appendTypeArg(e.buf, 3, uint64(len(x)))
		e.buf = append(e.buf, x...)
		return nil
	case []any:
		if err := e.preflightArray(len(x), depth); err != nil {
			return err
		}
		e.buf = appendTypeArg(e.buf, 4, uint64(len(x)))
		for _, elem := range x {
			if err := e.encodeValue(elem, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []string:
		if err := e.preflightArray(len(x), depth); err != nil {
			return err
		}
		e.buf = appendTypeArg(e.buf, 4, uint64(len(x)))
		for _, elem := range x {
			if err := e.encodeValue(elem, depth+1); err != nil {
				return err
			}
		}
		return nil
	case Map:
		return e.encodeMapSlice(x, depth)
	case map[string]any:
		return e.encodeGoMap(x, depth)
	case nil:
		return fmt.Errorf("%w: null is disallowed", ErrCBORUnsupported)
	default:
		return fmt.Errorf("%w: %T", ErrCBORUnsupported, v)
	}
}

type encodedMapEntry struct {
	keyBytes []byte
	entry    MapEntry
}

// preflightMapHeader validates depth, header byte width, remaining item budget,
// and minimum byte budget for a map of n entries BEFORE allocating any staging
// or sorting buffers. Returns the remaining byte budget available for all keys
// combined (reserving at least 1 byte for each of the n values).
func (e *cborEncoder) preflightMapHeader(n int, depth int) (int, error) {
	if depth >= e.lim.MaxDepth {
		return 0, fmt.Errorf("%w: depth > %d", ErrCBORLimitExceeded, e.lim.MaxDepth)
	}
	if n < 0 || uint64(n) > MaxCounter {
		return 0, ErrCBOROutOfDomain
	}
	hdr := typeArgLen(uint64(n))
	if err := e.checkSize(hdr); err != nil {
		return 0, err
	}
	remItems := e.lim.MaxItems - e.items
	remBytes := e.lim.MaxBytes - len(e.buf) - hdr
	// Each map entry consumes at least 2 items (key + value) and at least 2 bytes.
	if n > remItems/2 || n > remBytes/2 {
		return 0, fmt.Errorf("%w: map length %d exceeds remaining budget", ErrCBORLimitExceeded, n)
	}
	return remBytes - n, nil
}

func preflightMapKey(k string, remForKeys *int, maxBytes int) error {
	if uint64(len(k)) > MaxCounter {
		return ErrCBOROutOfDomain
	}
	if len(k) > *remForKeys {
		return fmt.Errorf("%w: encoded size > %d", ErrCBORLimitExceeded, maxBytes)
	}
	keyLen := typeArgLen(uint64(len(k))) + len(k)
	if keyLen > *remForKeys {
		return fmt.Errorf("%w: encoded size > %d", ErrCBORLimitExceeded, maxBytes)
	}
	if !isStrictASCIIKey(k) {
		return fmt.Errorf("%w: map key must be printable ASCII", ErrCBORUnsupported)
	}
	*remForKeys -= keyLen
	return nil
}

func (e *cborEncoder) encodeMapSlice(entries []MapEntry, depth int) error {
	remForKeys, err := e.preflightMapHeader(len(entries), depth)
	if err != nil {
		return err
	}
	// Preflight every key's encoded width and ASCII constraint with zero allocation
	// before allocating the sorting buffer.
	for _, ent := range entries {
		if err := preflightMapKey(ent.Key, &remForKeys, e.lim.MaxBytes); err != nil {
			return err
		}
	}
	sorted := make([]encodedMapEntry, len(entries))
	for i, ent := range entries {
		kb, err := encodeASCIIKey(ent.Key)
		if err != nil {
			return err
		}
		sorted[i] = encodedMapEntry{keyBytes: kb, entry: ent}
	}
	return e.finishEncodedMap(sorted, depth)
}

func (e *cborEncoder) encodeGoMap(m map[string]any, depth int) error {
	remForKeys, err := e.preflightMapHeader(len(m), depth)
	if err != nil {
		return err
	}
	// Preflight every key's encoded width and ASCII constraint with zero allocation
	// before allocating the sorting buffer.
	for k := range m {
		if err := preflightMapKey(k, &remForKeys, e.lim.MaxBytes); err != nil {
			return err
		}
	}
	sorted := make([]encodedMapEntry, 0, len(m))
	for k, val := range m {
		kb, err := encodeASCIIKey(k)
		if err != nil {
			return err
		}
		sorted = append(sorted, encodedMapEntry{keyBytes: kb, entry: MapEntry{Key: k, Value: val}})
	}
	return e.finishEncodedMap(sorted, depth)
}

func (e *cborEncoder) finishEncodedMap(sorted []encodedMapEntry, depth int) error {
	// RFC 8949 §4.2.1: deterministic map key sorting is bytewise lexicographic
	// order on the canonical encoded key bytes (shorter key length first for tstr).
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].keyBytes, sorted[j].keyBytes) < 0
	})
	for i := 1; i < len(sorted); i++ {
		if bytes.Equal(sorted[i-1].keyBytes, sorted[i].keyBytes) {
			return fmt.Errorf("%w: duplicate map key %q", ErrCBORNonCanonical, sorted[i].entry.Key)
		}
	}
	if err := e.checkSize(typeArgLen(uint64(len(sorted)))); err != nil {
		return err
	}
	e.buf = appendTypeArg(e.buf, 5, uint64(len(sorted)))
	for _, ent := range sorted {
		if err := e.countItem(); err != nil {
			return err
		}
		if err := e.checkSize(len(ent.keyBytes)); err != nil {
			return err
		}
		e.buf = append(e.buf, ent.keyBytes...)
		if err := e.encodeValue(ent.entry.Value, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// hashCanonicalCBOR streams the exact RFC 8949 §4.2.1 canonical CBOR encoding
// of v directly into SHA-256 without buffering the full preimage in memory.
// Wire inputs remain bounded by their respective profile limits at decode/encode
// boundaries, while enclosing domain-digest metadata never trips the 512 KiB
// single-buffer marshal cap.
func hashCanonicalCBOR(v any) ([32]byte, error) {
	var zero [32]byte
	h := sha256.New()
	enc := cborStreamEncoder{
		w:        h,
		maxDepth: DefaultMaxDepth,
		maxItems: DefaultMaxItems,
	}
	if err := enc.encodeValue(v, 0); err != nil {
		return zero, err
	}
	var out [32]byte
	h.Sum(out[:0])
	return out, nil
}

type cborStreamEncoder struct {
	w        io.Writer
	maxDepth int
	maxItems int
	items    int
	hdrBuf   [9]byte
}

func (e *cborStreamEncoder) countItem() error {
	e.items++
	if e.items > e.maxItems {
		return fmt.Errorf("%w: item count > %d", ErrCBORLimitExceeded, e.maxItems)
	}
	return nil
}

func (e *cborStreamEncoder) writeTypeArg(major byte, n uint64) error {
	b := appendTypeArg(e.hdrBuf[:0], major, n)
	_, err := e.w.Write(b)
	return err
}

func (e *cborStreamEncoder) encodeUint(n uint64) error {
	if n > MaxCounter {
		return fmt.Errorf("%w: %d", ErrCBOROutOfDomain, n)
	}
	return e.writeTypeArg(0, n)
}

func (e *cborStreamEncoder) encodeValue(v any, depth int) error {
	if err := e.countItem(); err != nil {
		return err
	}
	switch x := v.(type) {
	case uint64:
		return e.encodeUint(x)
	case uint:
		return e.encodeUint(uint64(x))
	case uint32:
		return e.encodeUint(uint64(x))
	case uint16:
		return e.encodeUint(uint64(x))
	case uint8:
		return e.encodeUint(uint64(x))
	case int:
		if x < 0 {
			return fmt.Errorf("%w: negative integer %d", ErrCBORUnsupported, x)
		}
		return e.encodeUint(uint64(x))
	case int64:
		if x < 0 {
			return fmt.Errorf("%w: negative integer %d", ErrCBORUnsupported, x)
		}
		return e.encodeUint(uint64(x))
	case bool:
		if x {
			e.hdrBuf[0] = 0xf5
		} else {
			e.hdrBuf[0] = 0xf4
		}
		_, err := e.w.Write(e.hdrBuf[:1])
		return err
	case []byte:
		if uint64(len(x)) > MaxCounter {
			return ErrCBOROutOfDomain
		}
		if err := e.writeTypeArg(2, uint64(len(x))); err != nil {
			return err
		}
		if len(x) > 0 {
			if _, err := e.w.Write(x); err != nil {
				return err
			}
		}
		return nil
	case string:
		if uint64(len(x)) > MaxCounter {
			return ErrCBOROutOfDomain
		}
		if !utf8.ValidString(x) {
			return fmt.Errorf("%w: invalid UTF-8 string", ErrCBORInvalid)
		}
		if err := e.writeTypeArg(3, uint64(len(x))); err != nil {
			return err
		}
		if len(x) > 0 {
			if _, err := io.WriteString(e.w, x); err != nil {
				return err
			}
		}
		return nil
	case []any:
		if depth >= e.maxDepth {
			return fmt.Errorf("%w: depth > %d", ErrCBORLimitExceeded, e.maxDepth)
		}
		if len(x) > e.maxItems-e.items {
			return fmt.Errorf("%w: array length %d exceeds remaining budget", ErrCBORLimitExceeded, len(x))
		}
		if err := e.writeTypeArg(4, uint64(len(x))); err != nil {
			return err
		}
		for _, elem := range x {
			if err := e.encodeValue(elem, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []string:
		if depth >= e.maxDepth {
			return fmt.Errorf("%w: depth > %d", ErrCBORLimitExceeded, e.maxDepth)
		}
		if len(x) > e.maxItems-e.items {
			return fmt.Errorf("%w: array length %d exceeds remaining budget", ErrCBORLimitExceeded, len(x))
		}
		if err := e.writeTypeArg(4, uint64(len(x))); err != nil {
			return err
		}
		for _, elem := range x {
			if err := e.encodeValue(elem, depth+1); err != nil {
				return err
			}
		}
		return nil
	case Map:
		return e.encodeMapSlice(x, depth)
	case map[string]any:
		return e.encodeGoMap(x, depth)
	case nil:
		return fmt.Errorf("%w: null is disallowed", ErrCBORUnsupported)
	default:
		return fmt.Errorf("%w: %T", ErrCBORUnsupported, v)
	}
}

func (e *cborStreamEncoder) preflightMap(n int, depth int) error {
	if depth >= e.maxDepth {
		return fmt.Errorf("%w: depth > %d", ErrCBORLimitExceeded, e.maxDepth)
	}
	if n < 0 || uint64(n) > MaxCounter {
		return ErrCBOROutOfDomain
	}
	if n > (e.maxItems-e.items)/2 {
		return fmt.Errorf("%w: map length %d exceeds remaining budget", ErrCBORLimitExceeded, n)
	}
	return nil
}

func (e *cborStreamEncoder) encodeMapSlice(entries []MapEntry, depth int) error {
	if err := e.preflightMap(len(entries), depth); err != nil {
		return err
	}
	remKeyBytes := DefaultMaxBytes
	for _, ent := range entries {
		if err := preflightMapKey(ent.Key, &remKeyBytes, DefaultMaxBytes); err != nil {
			return err
		}
	}
	sorted := make([]encodedMapEntry, len(entries))
	for i, ent := range entries {
		kb, err := encodeASCIIKey(ent.Key)
		if err != nil {
			return err
		}
		sorted[i] = encodedMapEntry{keyBytes: kb, entry: ent}
	}
	return e.finishEncodedMap(sorted, depth)
}

func (e *cborStreamEncoder) encodeGoMap(m map[string]any, depth int) error {
	if err := e.preflightMap(len(m), depth); err != nil {
		return err
	}
	remKeyBytes := DefaultMaxBytes
	for k := range m {
		if err := preflightMapKey(k, &remKeyBytes, DefaultMaxBytes); err != nil {
			return err
		}
	}
	sorted := make([]encodedMapEntry, 0, len(m))
	for k, val := range m {
		kb, err := encodeASCIIKey(k)
		if err != nil {
			return err
		}
		sorted = append(sorted, encodedMapEntry{keyBytes: kb, entry: MapEntry{Key: k, Value: val}})
	}
	return e.finishEncodedMap(sorted, depth)
}

func (e *cborStreamEncoder) finishEncodedMap(sorted []encodedMapEntry, depth int) error {
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].keyBytes, sorted[j].keyBytes) < 0
	})
	for i := 1; i < len(sorted); i++ {
		if bytes.Equal(sorted[i-1].keyBytes, sorted[i].keyBytes) {
			return fmt.Errorf("%w: duplicate map key %q", ErrCBORNonCanonical, sorted[i].entry.Key)
		}
	}
	if err := e.writeTypeArg(5, uint64(len(sorted))); err != nil {
		return err
	}
	for _, ent := range sorted {
		if err := e.countItem(); err != nil {
			return err
		}
		if _, err := e.w.Write(ent.keyBytes); err != nil {
			return err
		}
		if err := e.encodeValue(ent.entry.Value, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalCBORDefault decodes data using DefaultLimits.
func UnmarshalCBORDefault(data []byte) (any, error) {
	return UnmarshalCBOR(data, DefaultLimits())
}

// UnmarshalCBOR strictly decodes a single deterministic CBOR item in the LDR subset.
// Decoded values have Go types: uint64, []byte, string, []any, map[string]any, or bool.
func UnmarshalCBOR(data []byte, lim Limits) (any, error) {
	lim = lim.normalized()
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrCBORInvalid)
	}
	if len(data) > lim.MaxBytes {
		return nil, fmt.Errorf("%w: input size %d > %d", ErrCBORLimitExceeded, len(data), lim.MaxBytes)
	}
	dec := cborDecoder{data: data, lim: lim}
	v, err := dec.decodeValue(0)
	if err != nil {
		return nil, err
	}
	if dec.pos != len(dec.data) {
		return nil, fmt.Errorf("%w: %d extra bytes", ErrCBORTrailingBytes, len(dec.data)-dec.pos)
	}
	return v, nil
}

type cborDecoder struct {
	data  []byte
	pos   int
	lim   Limits
	items int
}

func (d *cborDecoder) countItem() error {
	d.items++
	if d.items > d.lim.MaxItems {
		return fmt.Errorf("%w: item count > %d", ErrCBORLimitExceeded, d.lim.MaxItems)
	}
	return nil
}

func (d *cborDecoder) readByte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, fmt.Errorf("%w: unexpected EOF", ErrCBORInvalid)
	}
	b := d.data[d.pos]
	d.pos++
	return b, nil
}

func (d *cborDecoder) readSlice(n uint64) ([]byte, error) {
	rem := uint64(len(d.data) - d.pos)
	if n > rem {
		return nil, fmt.Errorf("%w: truncated length %d (remaining %d)", ErrCBORInvalid, n, rem)
	}
	end := d.pos + int(n)
	out := make([]byte, int(n))
	copy(out, d.data[d.pos:end])
	d.pos = end
	return out, nil
}

// readArg decodes a canonical definite argument for major types 0..5.
// Rejects indefinite lengths (ai==31), reserved additional info (28..30),
// and non-shortest encodings.
func (d *cborDecoder) readArg(ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		b, err := d.readByte()
		if err != nil {
			return 0, err
		}
		if b < 24 {
			return 0, fmt.Errorf("%w: non-shortest uint %d in 1-byte form", ErrCBORNonCanonical, b)
		}
		return uint64(b), nil
	case ai == 25:
		if len(d.data)-d.pos < 2 {
			return 0, fmt.Errorf("%w: unexpected EOF in 2-byte arg", ErrCBORInvalid)
		}
		v := uint64(binary.BigEndian.Uint16(d.data[d.pos : d.pos+2]))
		d.pos += 2
		if v <= 0xff {
			return 0, fmt.Errorf("%w: non-shortest uint %d in 2-byte form", ErrCBORNonCanonical, v)
		}
		return v, nil
	case ai == 26:
		if len(d.data)-d.pos < 4 {
			return 0, fmt.Errorf("%w: unexpected EOF in 4-byte arg", ErrCBORInvalid)
		}
		v := uint64(binary.BigEndian.Uint32(d.data[d.pos : d.pos+4]))
		d.pos += 4
		if v <= 0xffff {
			return 0, fmt.Errorf("%w: non-shortest uint %d in 4-byte form", ErrCBORNonCanonical, v)
		}
		return v, nil
	case ai == 27:
		if len(d.data)-d.pos < 8 {
			return 0, fmt.Errorf("%w: unexpected EOF in 8-byte arg", ErrCBORInvalid)
		}
		v := binary.BigEndian.Uint64(d.data[d.pos : d.pos+8])
		d.pos += 8
		if v <= 0xffffffff {
			return 0, fmt.Errorf("%w: non-shortest uint %d in 8-byte form", ErrCBORNonCanonical, v)
		}
		return v, nil
	case ai == 31:
		return 0, fmt.Errorf("%w: indefinite length disallowed", ErrCBORNonCanonical)
	default:
		return 0, fmt.Errorf("%w: reserved additional info %d", ErrCBORInvalid, ai)
	}
}

func (d *cborDecoder) decodeValue(depth int) (any, error) {
	if err := d.countItem(); err != nil {
		return nil, err
	}
	ib, err := d.readByte()
	if err != nil {
		return nil, err
	}
	major := ib >> 5
	ai := ib & 0x1f

	switch major {
	case 0: // unsigned integer
		n, err := d.readArg(ai)
		if err != nil {
			return nil, err
		}
		if n > MaxCounter {
			return nil, fmt.Errorf("%w: %d", ErrCBOROutOfDomain, n)
		}
		return n, nil

	case 1: // negative integer — disallowed
		return nil, fmt.Errorf("%w: negative integer disallowed", ErrCBORUnsupported)

	case 2: // byte string
		n, err := d.readArg(ai)
		if err != nil {
			return nil, err
		}
		return d.readSlice(n)

	case 3: // text string
		n, err := d.readArg(ai)
		if err != nil {
			return nil, err
		}
		b, err := d.readSlice(n)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, fmt.Errorf("%w: invalid UTF-8 in text string", ErrCBORInvalid)
		}
		return string(b), nil

	case 4: // array
		if depth >= d.lim.MaxDepth {
			return nil, fmt.Errorf("%w: depth > %d", ErrCBORLimitExceeded, d.lim.MaxDepth)
		}
		n, err := d.readArg(ai)
		if err != nil {
			return nil, err
		}
		remItems := uint64(d.lim.MaxItems - d.items)
		remBytes := uint64(len(d.data) - d.pos)
		if n > remItems || n > remBytes {
			return nil, fmt.Errorf("%w: array length %d exceeds remaining budget", ErrCBORLimitExceeded, n)
		}
		initCap := int(n)
		if initCap > 64 {
			initCap = 64
		}
		out := make([]any, 0, initCap)
		for i := uint64(0); i < n; i++ {
			elem, err := d.decodeValue(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, elem)
		}
		return out, nil

	case 5: // map
		if depth >= d.lim.MaxDepth {
			return nil, fmt.Errorf("%w: depth > %d", ErrCBORLimitExceeded, d.lim.MaxDepth)
		}
		n, err := d.readArg(ai)
		if err != nil {
			return nil, err
		}
		remItems := uint64(d.lim.MaxItems - d.items)
		remBytes := uint64(len(d.data) - d.pos)
		// Each entry requires at least 2 items and 2 bytes (key + value).
		if n > remItems/2 || n > remBytes/2 {
			return nil, fmt.Errorf("%w: map length %d exceeds remaining budget", ErrCBORLimitExceeded, n)
		}
		initCap := int(n)
		if initCap > 64 {
			initCap = 64
		}
		out := make(map[string]any, initCap)
		var prevRawKey []byte
		for i := uint64(0); i < n; i++ {
			keyStart := d.pos
			if err := d.countItem(); err != nil {
				return nil, err
			}
			kib, err := d.readByte()
			if err != nil {
				return nil, err
			}
			if (kib >> 5) != 3 {
				return nil, fmt.Errorf("%w: map key must be ASCII text string (got major %d)", ErrCBORUnsupported, kib>>5)
			}
			klen, err := d.readArg(kib & 0x1f)
			if err != nil {
				return nil, err
			}
			kb, err := d.readSlice(klen)
			if err != nil {
				return nil, err
			}
			keyStr := string(kb)
			if !isStrictASCIIKey(keyStr) {
				return nil, fmt.Errorf("%w: map key must be printable ASCII", ErrCBORUnsupported)
			}
			rawKey := d.data[keyStart:d.pos]
			if i > 0 {
				cmp := bytes.Compare(prevRawKey, rawKey)
				if cmp == 0 {
					return nil, fmt.Errorf("%w: duplicate map key %q", ErrCBORNonCanonical, keyStr)
				}
				if cmp > 0 {
					return nil, fmt.Errorf("%w: map keys out of canonical order before %q", ErrCBORNonCanonical, keyStr)
				}
			}
			prevRawKey = rawKey
			val, err := d.decodeValue(depth + 1)
			if err != nil {
				return nil, err
			}
			out[keyStr] = val
		}
		return out, nil

	case 6: // semantic tag — disallowed
		return nil, fmt.Errorf("%w: semantic tags disallowed", ErrCBORUnsupported)

	case 7: // simple values / floats — only false (20) and true (21)
		switch ai {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, fmt.Errorf("%w: null disallowed", ErrCBORUnsupported)
		case 23:
			return nil, fmt.Errorf("%w: undefined disallowed", ErrCBORUnsupported)
		case 25, 26, 27:
			return nil, fmt.Errorf("%w: floats disallowed", ErrCBORUnsupported)
		case 31:
			return nil, fmt.Errorf("%w: unexpected break byte", ErrCBORNonCanonical)
		default:
			return nil, fmt.Errorf("%w: simple value %d disallowed", ErrCBORUnsupported, ai)
		}
	default:
		return nil, ErrCBORInvalid
	}
}

// Strict typed CBOR map accessors for schema decoding.

// RequireExactKeys verifies that m contains every key in required and no key
// outside required U optional.
func RequireExactKeys(m map[string]any, required []string, optional ...string) error {
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, k := range required {
		allowed[k] = struct{}{}
		if _, ok := m[k]; !ok {
			return fmt.Errorf("%w: missing required key %q", ErrCBORInvalid, k)
		}
	}
	for _, k := range optional {
		allowed[k] = struct{}{}
	}
	for k := range m {
		if _, ok := allowed[k]; !ok {
			return fmt.Errorf("%w: unknown key %q", ErrCBORInvalid, k)
		}
	}
	return nil
}

// MapUint extracts a required uint64 field from m.
func MapUint(m map[string]any, key string) (uint64, error) {
	v, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("%w: missing %q", ErrCBORInvalid, key)
	}
	n, ok := v.(uint64)
	if !ok {
		return 0, fmt.Errorf("%w: field %q must be uint", ErrCBORInvalid, key)
	}
	return n, nil
}

// MapOptionalUint distinguishes an absent key (ok=false) from an explicit 0 (ok=true, val=0).
func MapOptionalUint(m map[string]any, key string) (uint64, bool, error) {
	v, ok := m[key]
	if !ok {
		return 0, false, nil
	}
	n, ok := v.(uint64)
	if !ok {
		return 0, false, fmt.Errorf("%w: field %q must be uint", ErrCBORInvalid, key)
	}
	return n, true, nil
}

// MapBytes extracts a required byte string from m.
func MapBytes(m map[string]any, key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%w: missing %q", ErrCBORInvalid, key)
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: field %q must be bytes", ErrCBORInvalid, key)
	}
	return b, nil
}

// MapBytesLen extracts a required exact-length byte string from m.
func MapBytesLen(m map[string]any, key string, n int) ([]byte, error) {
	b, err := MapBytes(m, key)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("%w: field %q length %d != %d", ErrCBORInvalid, key, len(b), n)
	}
	return b, nil
}

// MapString extracts a required text string from m.
func MapString(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%w: missing %q", ErrCBORInvalid, key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: field %q must be string", ErrCBORInvalid, key)
	}
	return s, nil
}

// MapBool extracts a required boolean from m.
func MapBool(m map[string]any, key string) (bool, error) {
	v, ok := m[key]
	if !ok {
		return false, fmt.Errorf("%w: missing %q", ErrCBORInvalid, key)
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%w: field %q must be bool", ErrCBORInvalid, key)
	}
	return b, nil
}

// MapArray extracts a required array from m.
func MapArray(m map[string]any, key string) ([]any, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%w: missing %q", ErrCBORInvalid, key)
	}
	a, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: field %q must be array", ErrCBORInvalid, key)
	}
	return a, nil
}

// MapSubmap extracts a required map from m.
func MapSubmap(m map[string]any, key string) (map[string]any, error) {
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("%w: missing %q", ErrCBORInvalid, key)
	}
	sub, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: field %q must be map", ErrCBORInvalid, key)
	}
	return sub, nil
}
