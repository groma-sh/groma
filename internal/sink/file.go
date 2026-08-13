package sink

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// fileSink writes evidence to a directory, one subdirectory per run. It is the
// sink for air-gapped clusters, for a PersistentVolume mounted into the
// controller, and for trying the flow out before wiring up a registry.
type fileSink struct{ root string }

func newFileSink(c Config) (Sink, error) {
	if c.Path == "" {
		return nil, fmt.Errorf("evidence sink: a file sink needs a path")
	}
	return &fileSink{root: c.Path}, nil
}

func (s *fileSink) Name() string { return TypeFile }

func (s *fileSink) Write(_ context.Context, a Artifact) (string, error) {
	dir := filepath.Join(s.root, a.Run)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create evidence directory: %w", err)
	}
	for _, name := range a.FileNames() {
		// Evidence file names are Groma's own, but joining an attacker-supplied
		// name would escape the directory, so keep them flat by construction.
		path := filepath.Join(dir, filepath.Base(name))
		if err := os.WriteFile(path, a.Files[name], 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", path, err)
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir, nil
	}
	return "file://" + abs, nil
}
