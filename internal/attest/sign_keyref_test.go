package attest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	cosignsig "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

func TestNewKeySignerFileRoundTrip(t *testing.T) {
	keys, err := cosign.GenerateKeyPair(noPass)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "cosign.key")
	if err := os.WriteFile(keyPath, keys.PrivateBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	signer, err := NewKeySigner(context.Background(), keyPath)
	if err != nil {
		t.Fatal(err)
	}

	report, si := fixtureReport()
	stmt, err := BuildStatement(report, si, Meta{GromaVersion: "v0.4.0-test"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := stmt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	res, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := cosignsig.SignerVerifierFromKeyRef(context.Background(), keyPath, noPass, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := dsse.WrapSignerVerifier(verifier, intotoPayloadType).VerifySignature(bytes.NewReader(res.Envelope), nil); err != nil {
		t.Errorf("attestation signed via key file failed verification: %v", err)
	}
}
