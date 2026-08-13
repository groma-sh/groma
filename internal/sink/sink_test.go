package sink

import (
	"context"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func artifact() Artifact {
	return Artifact{
		Run: "pci-cde-hourly-28xkq",
		Files: map[string][]byte{
			"evidence.json":  []byte(`{"result":"FAIL"}`),
			"statement.json": []byte(`{"_type":"https://in-toto.io/Statement/v1"}`),
			"report.html":    []byte("<!doctype html><title>report</title>"),
		},
		Annotations: map[string]string{"groma.dev/result": "FAIL"},
	}
}

func TestParseURI(t *testing.T) {
	cases := []struct {
		raw  string
		want Config
	}{
		{"oci://registry.example.com/groma/evidence", Config{Type: TypeOCI, Repo: "registry.example.com/groma/evidence"}},
		{"s3://my-bucket/groma/evidence", Config{Type: TypeS3, Bucket: "my-bucket", Prefix: "groma/evidence"}},
		{"s3://my-bucket?region=eu-west-1", Config{Type: TypeS3, Bucket: "my-bucket", Region: "eu-west-1"}},
		{"gs://my-bucket/groma", Config{Type: TypeGCS, Bucket: "my-bucket", Prefix: "groma"}},
		{"gcs://my-bucket/groma", Config{Type: TypeGCS, Bucket: "my-bucket", Prefix: "groma"}},
		{"file:///var/lib/groma/evidence", Config{Type: TypeFile, Path: "/var/lib/groma/evidence"}},
		{"/var/lib/groma/evidence", Config{Type: TypeFile, Path: "/var/lib/groma/evidence"}},
		{"./evidence", Config{Type: TypeFile, Path: "./evidence"}},
	}
	for _, tc := range cases {
		got, err := ParseURI(tc.raw)
		if err != nil {
			t.Errorf("%q: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q = %+v, want %+v", tc.raw, got, tc.want)
		}
	}
}

func TestParseURI_Rejects(t *testing.T) {
	for _, raw := range []string{"", "ftp://host/path", "s3://", "oci://", "file://"} {
		if _, err := ParseURI(raw); err == nil {
			t.Errorf("%q parsed without error, but it names no usable destination", raw)
		}
	}
}

func TestNew_UnknownType(t *testing.T) {
	if _, err := New(context.Background(), Config{Type: "dropbox"}); err == nil {
		t.Error("an unknown sink type must be rejected at configuration time, not at publish time")
	}
}

func TestFileSink_WritesEveryFileUnderTheRun(t *testing.T) {
	root := t.TempDir()
	s, err := New(context.Background(), Config{Type: TypeFile, Path: root})
	if err != nil {
		t.Fatal(err)
	}
	a := artifact()
	ref, err := s.Write(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ref, "file://") || !strings.HasSuffix(ref, a.Run) {
		t.Errorf("ref = %q, want a file:// URI ending in the run name", ref)
	}
	for name, want := range a.Files {
		got, err := os.ReadFile(filepath.Join(root, a.Run, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s = %q, want %q: a sink must publish evidence byte-for-byte", name, got, want)
		}
	}
}

func TestOCISink_PushesEveryFileAsATitledLayer(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	host, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	repo := host.Host + "/groma/evidence"

	s, err := New(context.Background(), Config{Type: TypeOCI, Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	a := artifact()
	ref, err := s.Write(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ref, "@sha256:") {
		t.Errorf("ref = %q, want a digest reference: a tag can be moved, and evidence that can be swapped is not evidence", ref)
	}

	pulled, err := name.NewDigest(ref)
	if err != nil {
		t.Fatal(err)
	}
	img, err := remote.Image(pulled)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Layers) != len(a.Files) {
		t.Fatalf("pushed %d layers, want one per evidence file (%d)", len(manifest.Layers), len(a.Files))
	}
	titles := map[string]bool{}
	for _, l := range manifest.Layers {
		titles[l.Annotations[ociTitleAnnotation]] = true
	}
	for name := range a.Files {
		if !titles[name] {
			t.Errorf("layer for %q is missing its title annotation, so a puller cannot recover the file name", name)
		}
	}
	if manifest.Annotations["groma.dev/result"] != "FAIL" {
		t.Errorf("artifact annotations did not survive the push: %v", manifest.Annotations)
	}
}

func TestOCISink_PushIsDeterministic(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	host, _ := url.Parse(srv.URL)

	s, err := New(context.Background(), Config{Type: TypeOCI, Repo: host.Host + "/groma/evidence"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Write(context.Background(), artifact())
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Write(context.Background(), artifact())
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("the same evidence produced two digests (%s, %s); layer ordering must not depend on map iteration", first, second)
	}
}

func TestOCITag(t *testing.T) {
	cases := map[string]string{
		"pci-cde-hourly-28xkq": "pci-cde-hourly-28xkq",
		"-leading-dash":        "0leading-dash",
		"has/slash:and colon":  "has-slash-and-colon",
		"":                     "run",
	}
	for in, want := range cases {
		if got := ociTag(in); got != want {
			t.Errorf("ociTag(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ociTag(strings.Repeat("a", 200)); len(got) != 128 {
		t.Errorf("a long run name produced a %d-character tag, over the 128 limit", len(got))
	}
}
