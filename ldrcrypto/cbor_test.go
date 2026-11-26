package ldrcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestCBORRFC8949AppendixAVectors(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want string
	}{
		{"uint_0", uint64(0), "00"},
		{"uint_1", uint64(1), "01"},
		{"uint_10", uint64(10), "0a"},
		{"uint_23", uint64(23), "17"},
		{"uint_24", uint64(24), "1818"},
		{"uint_25", uint64(25), "1819"},
		{"uint_100", uint64(100), "1864"},
		{"uint_1000", uint64(1000), "1903e8"},
		{"uint_1000000", uint64(1000000), "1a000f4240"},
		{"uint_1000000000000", uint64(1000000000000), "1b000000e8d4a51000"},
		{"uint_max_counter", MaxCounter, "1b001fffffffffffff"},
		{"bool_false", false, "f4"},
		{"bool_true", true, "f5"},
		{"bstr_empty", []byte{}, "40"},
		{"bstr_4", []byte{1, 2, 3, 4}, "4401020304"},
		{"tstr_empty", "", "60"},
		{"tstr_a", "a", "6161"},
		{"tstr_IETF", "IETF", "6449455446"},
		{"tstr_utf8", "\u00fc", "62c3bc"},
		{"arr_empty", []any{}, "80"},
		{"arr_123", []any{uint64(1), uint64(2), uint64(3)}, "83010203"},
		{"arr_nested", []any{uint64(1), []any{uint64(2), uint64(3)}, []any{uint64(4), uint64(5)}}, "8301820203820405"},
		{"map_empty", Map{}, "a0"},
		{"map_ab", Map{{Key: "b", Value: []any{uint64(2), uint64(3)}}, {Key: "a", Value: uint64(1)}}, "a26161016162820203"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MarshalCBOR(tc.val)
			if err != nil {
				t.Fatalf("MarshalCBOR failed: %v", err)
			}
			wantBytes := mustHex(t, tc.want)
			if !bytes.Equal(got, wantBytes) {
				t.Fatalf("MarshalCBOR got %x, want %x", got, wantBytes)
			}
			decoded, err := UnmarshalCBORDefault(got)
			if err != nil {
				t.Fatalf("UnmarshalCBORDefault failed: %v", err)
			}
			reenc, err := MarshalCBOR(decoded)
			if err != nil {
				t.Fatalf("re-encode failed: %v", err)
			}
			if !bytes.Equal(reenc, wantBytes) {
				t.Fatalf("round-trip mismatch: got %x, want %x", reenc, wantBytes)
			}
		})
	}
}

func TestCBORCanonicalMapKeyOrderingRFC8949(t *testing.T) {
	// Under RFC 8949 §4.2.1 bytewise order on encoded keys:
	// "b" encodes as 61 62; "aa" encodes as 62 61 61.
	// 0x61 < 0x62, so shorter key "b" MUST precede longer key "aa"!
	m := Map{
		{Key: "aa", Value: uint64(2)},
		{Key: "b", Value: uint64(1)},
		{Key: "a", Value: uint64(0)},
		{Key: "z", Value: uint64(3)},
		{Key: "ab", Value: uint64(4)},
	}
	got, err := MarshalCBOR(m)
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}
	// Expected key order: "a", "b", "z", "aa", "ab"
	want := mustHex(t, "a5616100616201617a036261610262616204")
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical map order mismatch:\ngot:  %x\nwant: %x", got, want)
	}
	decoded, err := UnmarshalCBORDefault(got)
	if err != nil {
		t.Fatalf("UnmarshalCBORDefault: %v", err)
	}
	dm := decoded.(map[string]any)
	wantMap := map[string]any{"a": uint64(0), "b": uint64(1), "z": uint64(3), "aa": uint64(2), "ab": uint64(4)}
	if !reflect.DeepEqual(dm, wantMap) {
		t.Fatalf("decoded map mismatch: got %#v, want %#v", dm, wantMap)
	}

	// Lexicographic-string order ("aa" before "b") is NON-CANONICAL under RFC 8949 §4.2.1.
	badOrder := mustHex(t, "a262616102616201")
	if _, err := UnmarshalCBORDefault(badOrder); !errors.Is(err, ErrCBORNonCanonical) {
		t.Fatalf("expected ErrCBORNonCanonical for aa-before-b, got %v", err)
	}
}

func TestCBORNegativeRejections(t *testing.T) {
	cases := []struct {
		name    string
		hexData string
		wantErr error
	}{
		{"empty", "", ErrCBORInvalid},
		{"neg_int_-1", "20", ErrCBORUnsupported},
		{"neg_int_-100", "3863", ErrCBORUnsupported},
		{"semantic_tag_0", "c060", ErrCBORUnsupported},
		{"float16", "f90000", ErrCBORUnsupported},
		{"float32", "fa00000000", ErrCBORUnsupported},
		{"float64", "fb0000000000000000", ErrCBORUnsupported},
		{"null", "f6", ErrCBORUnsupported},
		{"undefined", "f7", ErrCBORUnsupported},
		{"simple_0", "e0", ErrCBORUnsupported},
		{"simple_32", "f820", ErrCBORUnsupported},
		{"break_byte", "ff", ErrCBORNonCanonical},
		{"indef_bstr", "5fff", ErrCBORNonCanonical},
		{"indef_tstr", "7fff", ErrCBORNonCanonical},
		{"indef_array", "9fff", ErrCBORNonCanonical},
		{"indef_map", "bfff", ErrCBORNonCanonical},
		{"non_shortest_uint_0_in_1b", "1800", ErrCBORNonCanonical},
		{"non_shortest_uint_23_in_1b", "1817", ErrCBORNonCanonical},
		{"non_shortest_uint_24_in_2b", "190018", ErrCBORNonCanonical},
		{"non_shortest_uint_255_in_2b", "1900ff", ErrCBORNonCanonical},
		{"non_shortest_uint_65535_in_4b", "1a0000ffff", ErrCBORNonCanonical},
		{"non_shortest_uint_maxu32_in_8b", "1b00000000ffffffff", ErrCBORNonCanonical},
		{"non_shortest_bstr_len", "5801aa", ErrCBORNonCanonical},
		{"non_shortest_tstr_len", "780161", ErrCBORNonCanonical},
		{"non_shortest_array_len", "9800", ErrCBORNonCanonical},
		{"non_shortest_map_len", "b800", ErrCBORNonCanonical},
		{"reserved_ai_28", "1c", ErrCBORInvalid},
		{"reserved_ai_29", "1d", ErrCBORInvalid},
		{"reserved_ai_30", "1e", ErrCBORInvalid},
		{"out_of_domain_2pow53", "1b0020000000000000", ErrCBOROutOfDomain},
		{"out_of_domain_maxu64", "1bffffffffffffffff", ErrCBOROutOfDomain},
		{"duplicate_map_keys", "a2616101616102", ErrCBORNonCanonical},
		{"reversed_map_keys", "a2616201616102", ErrCBORNonCanonical},
		{"int_map_key", "a10102", ErrCBORUnsupported},
		{"bstr_map_key", "a1416102", ErrCBORUnsupported},
		{"ctrl_char_map_key", "a1610001", ErrCBORUnsupported},
		{"non_ascii_map_key", "a162c3bc01", ErrCBORUnsupported},
		{"invalid_utf8_tstr", "62fffe", ErrCBORInvalid},
		{"trailing_bytes", "0102", ErrCBORTrailingBytes},
		{"truncated_uint", "1901", ErrCBORInvalid},
		{"truncated_bstr", "440102", ErrCBORInvalid},
		{"truncated_tstr", "646162", ErrCBORInvalid},
		{"huge_array_oom_guard", "9affffffff", ErrCBORLimitExceeded},
		{"huge_map_oom_guard", "baffffffff", ErrCBORLimitExceeded},
		{"huge_bstr_oom_guard", "5affffffff", ErrCBORInvalid},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustHex(t, tc.hexData)
			_, err := UnmarshalCBORDefault(raw)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("UnmarshalCBORDefault(%s): got err %v, want %v", tc.hexData, err, tc.wantErr)
			}
		})
	}
}

func TestCBOREncodeRejectionsAndLimits(t *testing.T) {
	if _, err := MarshalCBOR(MaxCounter + 1); !errors.Is(err, ErrCBOROutOfDomain) {
		t.Fatalf("expected ErrCBOROutOfDomain, got %v", err)
	}
	if _, err := MarshalCBOR(-1); !errors.Is(err, ErrCBORUnsupported) {
		t.Fatalf("expected ErrCBORUnsupported for negative int, got %v", err)
	}
	if _, err := MarshalCBOR(nil); !errors.Is(err, ErrCBORUnsupported) {
		t.Fatalf("expected ErrCBORUnsupported for nil, got %v", err)
	}
	if _, err := MarshalCBOR(3.14); !errors.Is(err, ErrCBORUnsupported) {
		t.Fatalf("expected ErrCBORUnsupported for float, got %v", err)
	}
	if _, err := MarshalCBOR(string([]byte{0xff, 0xfe})); !errors.Is(err, ErrCBORInvalid) {
		t.Fatalf("expected ErrCBORInvalid for bad UTF-8, got %v", err)
	}
	if _, err := MarshalCBOR(Map{{Key: "a", Value: 1}, {Key: "a", Value: 2}}); !errors.Is(err, ErrCBORNonCanonical) {
		t.Fatalf("expected ErrCBORNonCanonical for duplicate keys, got %v", err)
	}
	if _, err := MarshalCBOR(Map{{Key: "caf\u00e9", Value: 1}}); !errors.Is(err, ErrCBORUnsupported) {
		t.Fatalf("expected ErrCBORUnsupported for non-ASCII map key, got %v", err)
	}

	// Depth limit enforcement on both encode and decode.
	nested := any(uint64(1))
	for i := 0; i < 6; i++ {
		nested = []any{nested}
	}
	lim := Limits{MaxBytes: 1024, MaxDepth: 4, MaxItems: 100}
	if _, err := MarshalCBORWithLimits(nested, lim); !errors.Is(err, ErrCBORLimitExceeded) {
		t.Fatalf("expected encode depth limit error, got %v", err)
	}
	rawDeep, err := MarshalCBOR(nested)
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}
	if _, err := UnmarshalCBOR(rawDeep, lim); !errors.Is(err, ErrCBORLimitExceeded) {
		t.Fatalf("expected decode depth limit error, got %v", err)
	}

	// Item limit enforcement.
	arr := make([]any, 20)
	for i := range arr {
		arr[i] = uint64(i)
	}
	rawArr, err := MarshalCBOR(arr)
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}
	if _, err := UnmarshalCBOR(rawArr, Limits{MaxBytes: 1024, MaxDepth: 8, MaxItems: 10}); !errors.Is(err, ErrCBORLimitExceeded) {
		t.Fatalf("expected decode item limit error, got %v", err)
	}

	// Byte limit enforcement.
	if _, err := UnmarshalCBOR(rawArr, Limits{MaxBytes: 5, MaxDepth: 8, MaxItems: 100}); !errors.Is(err, ErrCBORLimitExceeded) {
		t.Fatalf("expected decode byte limit error, got %v", err)
	}
}

func TestCBORAbsentVsExplicitZero(t *testing.T) {
	em := ExpectMap{
		"key_epoch":     0,
		"lifecycle_rev": 0,
		"turn_count":    3,
	}
	cm, err := em.ToCBORMap()
	if err != nil {
		t.Fatalf("ToCBORMap: %v", err)
	}
	raw, err := MarshalCBOR(cm)
	if err != nil {
		t.Fatalf("MarshalCBOR: %v", err)
	}
	dec, err := UnmarshalCBORDefault(raw)
	if err != nil {
		t.Fatalf("UnmarshalCBORDefault: %v", err)
	}
	m := dec.(map[string]any)
	v, ok, err := MapOptionalUint(m, "key_epoch")
	if err != nil || !ok || v != 0 {
		t.Fatalf("key_epoch: got (%d, %v, %v), want (0, true, nil)", v, ok, err)
	}
	v2, ok2, err := MapOptionalUint(m, "root_rev")
	if err != nil || ok2 || v2 != 0 {
		t.Fatalf("absent root_rev: got (%d, %v, %v), want (0, false, nil)", v2, ok2, err)
	}
	parsed, err := ParseExpectMap(dec)
	if err != nil {
		t.Fatalf("ParseExpectMap: %v", err)
	}
	if _, exists := parsed["root_rev"]; exists {
		t.Fatalf("absent root_rev must remain absent")
	}
	if val, exists := parsed["key_epoch"]; !exists || val != 0 {
		t.Fatalf("explicit zero key_epoch lost: exists=%v val=%d", exists, val)
	}
}

// TestCBORExactWidthByteLimitsAndEncodeDecodeParity verifies Codex Turn 34:
//   - Encoder charges exact canonical CBOR header widths (1/2/3/5/9 bytes) rather
//     than overestimating 9 bytes, so MarshalCBORWithLimits and UnmarshalCBOR agree
//     at exact-fit and one-byte-over budgets across integers, bstr, tstr, arrays,
//     maps (both Map and map[string]any), and near DefaultMaxBytes.
func TestCBORExactWidthByteLimitsAndEncodeDecodeParity(t *testing.T) {
	cases := []struct {
		name      string
		val       any
		wantBytes int
	}{
		{"uint_0_1B", uint64(0), 1},
		{"uint_23_1B", uint64(23), 1},
		{"uint_24_2B", uint64(24), 2},
		{"uint_255_2B", uint64(255), 2},
		{"uint_256_3B", uint64(256), 3},
		{"uint_65535_3B", uint64(65535), 3},
		{"uint_65536_5B", uint64(65536), 5},
		{"uint_maxu32_5B", uint64(0xffffffff), 5},
		{"uint_u32_plus_1_9B", uint64(0x100000000), 9},
		{"uint_max_counter_9B", MaxCounter, 9},
		{"bool_true_1B", true, 1},
		{"bstr_empty_1B", []byte{}, 1},
		{"bstr_23_24B", bytes.Repeat([]byte{0xab}, 23), 24},
		{"bstr_24_26B", bytes.Repeat([]byte{0xab}, 24), 26},
		{"bstr_256_259B", bytes.Repeat([]byte{0xab}, 256), 259},
		{"tstr_empty_1B", "", 1},
		{"tstr_23_24B", strings.Repeat("a", 23), 24},
		{"tstr_24_26B", strings.Repeat("a", 24), 26},
		{"tstr_256_259B", strings.Repeat("a", 256), 259},
		{"arr_empty_1B", []any{}, 1},
		{"arr_one_zero_2B", []any{uint64(0)}, 2},
		{"str_arr_one_3B", []string{"a"}, 3},
		{"map_empty_1B", Map{}, 1},
		{"gomap_empty_1B", map[string]any{}, 1},
		{"map_single_4B", Map{{Key: "a", Value: uint64(0)}}, 4},
		{"gomap_single_4B", map[string]any{"a": uint64(0)}, 4},
		// Near DefaultMaxBytes (524288): 5-byte length header + 524283 payload = 524288 exact fit.
		{"bstr_exact_default_max", make([]byte, DefaultMaxBytes-5), DefaultMaxBytes},
		{"tstr_exact_default_max", strings.Repeat("x", DefaultMaxBytes-5), DefaultMaxBytes},
		// Container near DefaultMaxBytes: a1 (1B) + 61 64 (2B) + 5a <4B> (5B) + 524280B = 524288 exact fit.
		{"map_container_exact_default_max", Map{{Key: "d", Value: make([]byte, DefaultMaxBytes-8)}}, DefaultMaxBytes},
		{"gomap_container_exact_default_max", map[string]any{"d": make([]byte, DefaultMaxBytes-8)}, DefaultMaxBytes},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			exactLim := Limits{MaxBytes: tc.wantBytes, MaxDepth: DefaultMaxDepth, MaxItems: DefaultMaxItems}
			enc, err := MarshalCBORWithLimits(tc.val, exactLim)
			if err != nil {
				t.Fatalf("MarshalCBORWithLimits(exact %dB) failed: %v", tc.wantBytes, err)
			}
			if len(enc) != tc.wantBytes {
				t.Fatalf("encoded len = %d, want %d", len(enc), tc.wantBytes)
			}
			dec, err := UnmarshalCBOR(enc, exactLim)
			if err != nil {
				t.Fatalf("UnmarshalCBOR(exact %dB) failed: %v", tc.wantBytes, err)
			}
			reenc, err := MarshalCBORWithLimits(dec, exactLim)
			if err != nil {
				t.Fatalf("re-encode(exact %dB) failed: %v", tc.wantBytes, err)
			}
			if !bytes.Equal(reenc, enc) {
				t.Fatalf("round-trip byte mismatch at exact limit %dB", tc.wantBytes)
			}

			// One byte over the limit MUST fail identically on both encode and decode!
			if tc.wantBytes > 1 {
				tightLim := Limits{MaxBytes: tc.wantBytes - 1, MaxDepth: DefaultMaxDepth, MaxItems: DefaultMaxItems}
				if _, err := MarshalCBORWithLimits(tc.val, tightLim); !errors.Is(err, ErrCBORLimitExceeded) {
					t.Fatalf("MarshalCBORWithLimits(1B under=%d): got %v, want ErrCBORLimitExceeded", tightLim.MaxBytes, err)
				}
				if _, err := UnmarshalCBOR(enc, tightLim); !errors.Is(err, ErrCBORLimitExceeded) {
					t.Fatalf("UnmarshalCBOR(1B under=%d): got %v, want ErrCBORLimitExceeded", tightLim.MaxBytes, err)
				}
			}
		})
	}

	// Default-limit (+1 byte over DefaultMaxBytes) checks for bstr, tstr, and map container.
	overCases := []struct {
		name string
		val  any
	}{
		{"bstr_default_plus_1", make([]byte, DefaultMaxBytes-4)},
		{"tstr_default_plus_1", strings.Repeat("x", DefaultMaxBytes-4)},
		{"map_container_default_plus_1", Map{{Key: "d", Value: make([]byte, DefaultMaxBytes-7)}}},
		{"gomap_container_default_plus_1", map[string]any{"d": make([]byte, DefaultMaxBytes-7)}},
	}
	for _, tc := range overCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MarshalCBOR(tc.val); !errors.Is(err, ErrCBORLimitExceeded) {
				t.Fatalf("MarshalCBOR(%s): got %v, want ErrCBORLimitExceeded", tc.name, err)
			}
			// Encode with +1 larger cap, then verify UnmarshalCBORDefault also rejects!
			enc, err := MarshalCBORWithLimits(tc.val, Limits{MaxBytes: DefaultMaxBytes + 1, MaxDepth: DefaultMaxDepth, MaxItems: DefaultMaxItems})
			if err != nil {
				t.Fatalf("MarshalCBORWithLimits(+1 cap): %v", err)
			}
			if len(enc) != DefaultMaxBytes+1 {
				t.Fatalf("len = %d, want %d", len(enc), DefaultMaxBytes+1)
			}
			if _, err := UnmarshalCBORDefault(enc); !errors.Is(err, ErrCBORLimitExceeded) {
				t.Fatalf("UnmarshalCBORDefault(%s): got %v, want ErrCBORLimitExceeded", tc.name, err)
			}
		})
	}
}

// TestCBORMapBudgetPreflightBeforeAllocation verifies Codex Turn 34:
// Both Map and map[string]any reject item-budget, byte-budget, depth-budget,
// and oversized-key violations BEFORE allocating sorting/staging buffers.
func TestCBORMapBudgetPreflightBeforeAllocation(t *testing.T) {
	const bigN = 20000
	bigMap := make(Map, bigN)
	bigGoMap := make(map[string]any, bigN)
	for i := 0; i < bigN; i++ {
		k := fmt.Sprintf("k%06d", i)
		bigMap[i] = MapEntry{Key: k, Value: uint64(0)}
		bigGoMap[k] = uint64(0)
	}
	bigKey := strings.Repeat("k", 256*1024)
	bigKeyMap := Map{{Key: bigKey, Value: uint64(0)}}
	bigKeyGoMap := map[string]any{bigKey: uint64(0)}

	cases := []struct {
		name string
		val  any
		lim  Limits
	}{
		{"Map_exceeds_max_items", bigMap, Limits{MaxBytes: 10 << 20, MaxDepth: 8, MaxItems: 100}},
		{"GoMap_exceeds_max_items", bigGoMap, Limits{MaxBytes: 10 << 20, MaxDepth: 8, MaxItems: 100}},
		{"Map_exceeds_max_bytes", bigMap, Limits{MaxBytes: 1024, MaxDepth: 8, MaxItems: 100000}},
		{"GoMap_exceeds_max_bytes", bigGoMap, Limits{MaxBytes: 1024, MaxDepth: 8, MaxItems: 100000}},
		{"Map_exceeds_max_depth", []any{bigMap}, Limits{MaxBytes: 10 << 20, MaxDepth: 1, MaxItems: 100000}},
		{"GoMap_exceeds_max_depth", []any{bigGoMap}, Limits{MaxBytes: 10 << 20, MaxDepth: 1, MaxItems: 100000}},
		{"Map_oversized_key_exceeds_max_bytes", bigKeyMap, Limits{MaxBytes: 1024, MaxDepth: 8, MaxItems: 100}},
		{"GoMap_oversized_key_exceeds_max_bytes", bigKeyGoMap, Limits{MaxBytes: 1024, MaxDepth: 8, MaxItems: 100}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := MarshalCBORWithLimits(tc.val, tc.lim)
			runtime.ReadMemStats(&after)
			if !errors.Is(err, ErrCBORLimitExceeded) {
				t.Fatalf("%s: got %v, want ErrCBORLimitExceeded", tc.name, err)
			}
			// Staging 20,000 entries or a 256 KiB encoded key would allocate >> 256 KiB;
			// preflight rejection should allocate only the small error string (< 64 KiB even under -race).
			delta := after.TotalAlloc - before.TotalAlloc
			if delta > 64*1024 {
				t.Fatalf("%s allocated %d bytes before failing budget check (want <= 65536)", tc.name, delta)
			}
		})
	}
}
