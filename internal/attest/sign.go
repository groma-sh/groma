package attest

import (
	"bytes"
	"context"
	"crypto"
	"fmt"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cosignsig "github.com/sigstore/cosign/v2/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	sigopts "github.com/sigstore/sigstore/pkg/signature/options"
)

const intotoPayloadType = "application/vnd.in-toto+json"

type SignResult struct {
	Envelope      []byte
	CertChainPEM  []byte
	RekorLogIndex int64
}

type Signer interface {
	Sign(ctx context.Context, statement []byte) (*SignResult, error)
}

func noPass(bool) ([]byte, error) { return nil, nil }

type keySigner struct{ sv signature.SignerVerifier }

func NewKeySigner(ctx context.Context, keyRef string) (Signer, error) {
	sv, err := cosignsig.SignerVerifierFromKeyRef(ctx, keyRef, noPass, nil)
	if err != nil {
		return nil, fmt.Errorf("load signing key %q: %w", keyRef, err)
	}
	return &keySigner{sv: sv}, nil
}

func (k *keySigner) Sign(ctx context.Context, statement []byte) (*SignResult, error) {
	env, err := signDSSE(ctx, k.sv, statement)
	if err != nil {
		return nil, err
	}
	return &SignResult{Envelope: env}, nil
}

type KeylessOptions struct {
	FulcioURL    string
	RekorURL     string
	OIDCIssuer   string
	OIDCClientID string

	IDToken string

	UploadTLog bool
}

func (o *KeylessOptions) defaults() {
	if o.FulcioURL == "" {
		o.FulcioURL = options.DefaultFulcioURL
	}
	if o.RekorURL == "" {
		o.RekorURL = options.DefaultRekorURL
	}
	if o.OIDCIssuer == "" {
		o.OIDCIssuer = options.DefaultOIDCIssuerURL
	}
	if o.OIDCClientID == "" {
		o.OIDCClientID = "sigstore"
	}
}

type keylessSigner struct{ opts KeylessOptions }

func NewKeylessSigner(opts KeylessOptions) Signer {
	opts.defaults()
	return &keylessSigner{opts: opts}
}

func (k *keylessSigner) Sign(ctx context.Context, statement []byte) (*SignResult, error) {
	priv, err := cosign.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	sv, err := signature.LoadSignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	ko := options.KeyOpts{
		FulcioURL:    k.opts.FulcioURL,
		RekorURL:     k.opts.RekorURL,
		OIDCIssuer:   k.opts.OIDCIssuer,
		OIDCClientID: k.opts.OIDCClientID,
		IDToken:      k.opts.IDToken,
	}
	flc, err := fulcio.NewSigner(ctx, ko, sv)
	if err != nil {
		return nil, fmt.Errorf("obtain fulcio signing certificate: %w", err)
	}
	env, err := signDSSE(ctx, flc, statement)
	if err != nil {
		return nil, err
	}
	res := &SignResult{
		Envelope:     env,
		CertChainPEM: append(append([]byte{}, flc.Cert...), flc.Chain...),
	}
	if k.opts.UploadTLog {
		rc, err := rekor.NewClient(k.opts.RekorURL)
		if err != nil {
			return nil, fmt.Errorf("rekor client: %w", err)
		}
		entry, err := cosign.TLogUploadInTotoAttestation(ctx, rc, env, flc.Cert)
		if err != nil {
			return nil, fmt.Errorf("upload attestation to rekor: %w", err)
		}
		if entry.LogIndex != nil {
			res.RekorLogIndex = *entry.LogIndex
		}
	}
	return res, nil
}

func signDSSE(ctx context.Context, sv signature.SignerVerifier, statement []byte) ([]byte, error) {
	env, err := dsse.WrapSigner(sv, intotoPayloadType).SignMessage(bytes.NewReader(statement), sigopts.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("sign attestation: %w", err)
	}
	return env, nil
}
