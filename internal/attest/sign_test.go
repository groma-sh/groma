package attest

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

func newTestKeySigner(t *testing.T) (Signer, signature.SignerVerifier) {
	t.Helper()
	priv, err := cosign.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sv, err := signature.LoadSignerVerifier(priv, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return &keySigner{sv: sv}, sv
}

func TestKeySignerRoundTrip(t *testing.T) {
	report, si := fixtureReport()
	stmt, err := BuildStatement(report, si, Meta{GromaVersion: "v0.4.0-test"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := stmt.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	signer, sv := newTestKeySigner(t)
	res, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}

	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(res.Envelope, &env); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if env.PayloadType != intotoPayloadType {
		t.Errorf("payloadType = %q, want %q", env.PayloadType, intotoPayloadType)
	}
	gotPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("envelope payload does not round-trip to the signed statement")
	}
	if len(env.Signatures) == 0 || env.Signatures[0].Sig == "" {
		t.Fatalf("envelope carries no signature")
	}

	if err := dsse.WrapSignerVerifier(sv, intotoPayloadType).VerifySignature(bytes.NewReader(res.Envelope), nil); err != nil {
		t.Errorf("valid envelope failed verification: %v", err)
	}

	tampered := bytes.Replace(res.Envelope, []byte(env.Payload), []byte(base64.StdEncoding.EncodeToString(append(payload, '!'))), 1)
	if err := dsse.WrapSignerVerifier(sv, intotoPayloadType).VerifySignature(bytes.NewReader(tampered), nil); err == nil {
		t.Errorf("tampered envelope passed verification")
	}

	if res.CertChainPEM != nil || res.RekorLogIndex != 0 {
		t.Errorf("key signer should not produce a cert chain or rekor entry")
	}
}
