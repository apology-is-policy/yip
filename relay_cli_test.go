package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/apology-is-policy/yip/ldrcrypto"
)

func TestRelayCLIInitProvisionAndStatus(t *testing.T) {
	dir := t.TempDir()

	// 1. yip relay init
	var initBuf bytes.Buffer
	if err := RelayCLI([]string{"init", "--dir", dir, "--hosts", "127.0.0.1,localhost"}, &initBuf); err != nil {
		t.Fatalf("relay init: %v", err)
	}
	var initOut struct {
		Cert          string `json:"cert"`
		Key           string `json:"key"`
		PinSPKISHA256 string `json:"pin_spki_sha256"`
	}
	if err := json.Unmarshal(initBuf.Bytes(), &initOut); err != nil {
		t.Fatalf("decode init JSON: %v", err)
	}
	pinBytes, err := hex.DecodeString(initOut.PinSPKISHA256)
	if err != nil || len(pinBytes) != 32 {
		t.Fatalf("invalid pin_spki_sha256: %q", initOut.PinSPKISHA256)
	}

	// 2. Create root-signed descriptor and run `yip relay provision`.
	r1, _ := ldrcrypto.GenerateEd25519Key()
	r2, _ := ldrcrypto.GenerateECDSAP256Key()
	lineID := bytes.Repeat([]byte{0x7a}, 16)
	desc := ldrcrypto.CreationDescriptor{
		Version:    1,
		LineID:     lineID,
		Generation: 1,
		RootKeys:   []ldrcrypto.PublicKey{r1.PublicKey(), r2.PublicKey()},
		RelayOrigin: ldrcrypto.RelayOrigin{
			URL:            "https://127.0.0.1:8443",
			TLSPolicy:      ldrcrypto.TLSPolicyPinSPKISHA256,
			TLSPin:         pinBytes,
			SessionBinding: ldrcrypto.SessionBindingTLS13Exporter,
		},
		Profile: ldrcrypto.ProfileV1(),
	}
	signed, err := ldrcrypto.SignCreationDescriptor(r1, desc)
	if err != nil {
		t.Fatal(err)
	}
	rawDesc, err := signed.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	descFile := filepath.Join(t.TempDir(), "line.desc.cbor")
	if err := os.WriteFile(descFile, rawDesc, 0o600); err != nil {
		t.Fatal(err)
	}

	var provBuf bytes.Buffer
	if err := RelayCLI([]string{"provision", "--dir", dir, "--descriptor", descFile}, &provBuf); err != nil {
		t.Fatalf("relay provision: %v", err)
	}
	var provOut struct {
		LineID           string `json:"line_id"`
		DescriptorDigest string `json:"descriptor_digest"`
		GenesisAnchor    string `json:"genesis_anchor"`
	}
	if err := json.Unmarshal(provBuf.Bytes(), &provOut); err != nil {
		t.Fatalf("decode provision JSON: %v", err)
	}
	if provOut.LineID != hex.EncodeToString(lineID) {
		t.Fatalf("provision line_id mismatch: %s", provOut.LineID)
	}

	// 3. yip relay status
	var stBuf bytes.Buffer
	if err := RelayCLI([]string{"status", "--dir", dir}, &stBuf); err != nil {
		t.Fatalf("relay status: %v", err)
	}
	var stOut struct {
		Lines []struct {
			LineID string `json:"line_id"`
		} `json:"lines"`
	}
	if err := json.Unmarshal(stBuf.Bytes(), &stOut); err != nil {
		t.Fatalf("decode status JSON: %v", err)
	}
	if len(stOut.Lines) != 1 || stOut.Lines[0].LineID != hex.EncodeToString(lineID) {
		t.Fatalf("status mismatch: %+v", stOut)
	}
}
