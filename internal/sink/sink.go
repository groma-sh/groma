// Package sink publishes a conformance run's evidence somewhere durable.
//
// Evidence that only exists in a ConfigMap in the cluster it audits is not
// evidence an auditor can rely on: the cluster under test can rewrite it, and
// it disappears with the namespace. A sink copies the same bytes the controller
// signed to storage outside that blast radius, and returns a reference the run's
// status can point at.
//
// Sinks never transform what they publish. The signed statement, the DSSE
// envelope, and the deterministic HTML render travel byte-for-byte, so a
// verifier fetching from a sink checks the same signature as one reading the
// in-cluster ConfigMap.
package sink

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Artifact is one run's evidence bundle.
type Artifact struct {
	// Run names the run, and becomes the object prefix or OCI tag.
	Run string
	// Files maps a file name ("statement.json") to its exact bytes.
	Files map[string][]byte
	// Annotations travel with the artifact where the backend supports them.
	Annotations map[string]string
}

// FileNames lists the artifact's files in a stable order, so a bundle published
// twice produces the same layer ordering and therefore the same digest.
func (a Artifact) FileNames() []string {
	names := make([]string, 0, len(a.Files))
	for name := range a.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Sink publishes evidence and returns a reference to what it wrote.
type Sink interface {
	// Name is the sink type ("oci", "s3", "gcs", "file").
	Name() string
	// Write publishes the artifact and returns a reference an auditor can
	// resolve: a digest-pinned OCI reference, or a storage URI.
	Write(ctx context.Context, a Artifact) (string, error)
}

// Config describes one sink. Only the fields its Type uses are read.
type Config struct {
	Type string
	// Repo is the OCI repository, without a tag ("registry.example.com/groma/evidence").
	Repo string
	// Bucket and Prefix address object storage; Region is S3 only.
	Bucket string
	Prefix string
	Region string
	// Path is the directory a file sink writes under.
	Path string
}

const (
	TypeOCI  = "oci"
	TypeS3   = "s3"
	TypeGCS  = "gcs"
	TypeFile = "file"
)

// New builds the sink a Config describes.
func New(ctx context.Context, c Config) (Sink, error) {
	switch strings.ToLower(strings.TrimSpace(c.Type)) {
	case "":
		return nil, fmt.Errorf("evidence sink: type is required")
	case TypeOCI:
		return newOCISink(c)
	case TypeS3:
		return newS3Sink(ctx, c)
	case TypeGCS:
		return newGCSSink(ctx, c)
	case TypeFile:
		return newFileSink(c)
	default:
		return nil, fmt.Errorf("evidence sink: unknown type %q (want %s, %s, %s, or %s)",
			c.Type, TypeOCI, TypeS3, TypeGCS, TypeFile)
	}
}

// ParseURI turns a single-string sink spec into a Config, which is how the CLI
// takes one:
//
//	oci://registry.example.com/groma/evidence
//	s3://my-bucket/groma/evidence?region=eu-west-1
//	gs://my-bucket/groma/evidence
//	file:///var/lib/groma/evidence
//	/var/lib/groma/evidence
func ParseURI(raw string) (Config, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Config{}, fmt.Errorf("evidence sink: empty specification")
	}
	// A bare path is the friendliest thing to type for a local run.
	if !strings.Contains(raw, "://") {
		return Config{Type: TypeFile, Path: raw}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Config{}, fmt.Errorf("evidence sink %q: %w", raw, err)
	}
	path := strings.Trim(u.Path, "/")

	switch strings.ToLower(u.Scheme) {
	case TypeOCI:
		repo := u.Host
		if path != "" {
			repo += "/" + path
		}
		if repo == "" {
			return Config{}, fmt.Errorf("evidence sink %q: an oci:// sink needs a repository", raw)
		}
		return Config{Type: TypeOCI, Repo: repo}, nil
	case "s3":
		if u.Host == "" {
			return Config{}, fmt.Errorf("evidence sink %q: an s3:// sink needs a bucket", raw)
		}
		return Config{Type: TypeS3, Bucket: u.Host, Prefix: path, Region: u.Query().Get("region")}, nil
	case "gs", "gcs":
		if u.Host == "" {
			return Config{}, fmt.Errorf("evidence sink %q: a gs:// sink needs a bucket", raw)
		}
		return Config{Type: TypeGCS, Bucket: u.Host, Prefix: path}, nil
	case "file":
		// file:///abs/path leaves an empty host; file://relative/path does not.
		p := u.Path
		if u.Host != "" {
			p = u.Host + u.Path
		}
		if p == "" {
			return Config{}, fmt.Errorf("evidence sink %q: a file:// sink needs a path", raw)
		}
		return Config{Type: TypeFile, Path: p}, nil
	default:
		return Config{}, fmt.Errorf("evidence sink %q: unknown scheme %q (want oci, s3, gs, or file)", raw, u.Scheme)
	}
}

// objectKey joins a prefix, the run name, and a file name into a storage key.
func objectKey(prefix, run, file string) string {
	parts := make([]string, 0, 3)
	if p := strings.Trim(prefix, "/"); p != "" {
		parts = append(parts, p)
	}
	return strings.Join(append(parts, run, file), "/")
}
