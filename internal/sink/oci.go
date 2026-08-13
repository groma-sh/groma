package sink

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Evidence is pushed as an OCI artifact: one layer per file, each titled with
// the standard annotation so `oras pull` and `crane export` recover the original
// names. Using the registry the cluster already trusts for images means the
// evidence inherits its access control, replication, and retention.
const (
	ociConfigMediaType = types.MediaType("application/vnd.groma.evidence.config.v1+json")
	ociLayerMediaType  = types.MediaType("application/vnd.groma.evidence.file.v1")
	ociTitleAnnotation = "org.opencontainers.image.title"
)

type ociSink struct {
	repo    name.Repository
	options []remote.Option
}

func newOCISink(c Config) (Sink, error) {
	if c.Repo == "" {
		return nil, fmt.Errorf("evidence sink: an oci sink needs a repo")
	}
	repo, err := name.NewRepository(c.Repo)
	if err != nil {
		return nil, fmt.Errorf("evidence sink: repo %q: %w", c.Repo, err)
	}
	return &ociSink{
		repo: repo,
		// The default keychain reads the same credentials the node's container
		// runtime uses, so a registry that already works for images works here.
		options: []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
	}, nil
}

func (s *ociSink) Name() string { return TypeOCI }

func (s *ociSink) Write(ctx context.Context, a Artifact) (string, error) {
	img, err := s.build(a)
	if err != nil {
		return "", err
	}
	tag := s.repo.Tag(ociTag(a.Run))
	opts := append([]remote.Option{remote.WithContext(ctx)}, s.options...)
	if err := remote.Write(tag, img, opts...); err != nil {
		return "", fmt.Errorf("push evidence to %s: %w", tag, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return "", err
	}
	// The digest reference is what goes in the run's status: a tag can be moved,
	// a digest cannot, and evidence that can be swapped is not evidence.
	return s.repo.Digest(digest.String()).String(), nil
}

func (s *ociSink) build(a Artifact) (v1.Image, error) {
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, ociConfigMediaType)

	addenda := make([]mutate.Addendum, 0, len(a.Files))
	for _, fileName := range a.FileNames() {
		addenda = append(addenda, mutate.Addendum{
			Layer:       static.NewLayer(a.Files[fileName], ociLayerMediaType),
			Annotations: map[string]string{ociTitleAnnotation: fileName},
		})
	}
	img, err := mutate.Append(img, addenda...)
	if err != nil {
		return nil, fmt.Errorf("assemble evidence artifact: %w", err)
	}
	if len(a.Annotations) > 0 {
		annotated, ok := mutate.Annotations(img, a.Annotations).(v1.Image)
		if !ok {
			return nil, fmt.Errorf("annotate evidence artifact")
		}
		img = annotated
	}
	return img, nil
}

// ociTag makes a run name safe to use as a tag. Run names are generated from a
// schedule name and a suffix, which can exceed the 128-character tag limit and
// can contain characters tags disallow.
func ociTag(run string) string {
	const maxTagLength = 128
	out := make([]rune, 0, len(run))
	for _, r := range run {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "run"
	}
	// A tag may not begin with a period or a dash.
	if out[0] == '.' || out[0] == '-' {
		out[0] = '0'
	}
	if len(out) > maxTagLength {
		out = out[:maxTagLength]
	}
	return string(out)
}
