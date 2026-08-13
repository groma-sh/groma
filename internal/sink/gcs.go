package sink

import (
	"context"
	"fmt"

	"cloud.google.com/go/storage"
)

// gcsSink writes one object per evidence file under <prefix>/<run>/.
// Credentials come from Application Default Credentials, so in-cluster the
// recommended setup is Workload Identity rather than a mounted service-account
// key.
type gcsSink struct {
	client *storage.Client
	bucket string
	prefix string
}

func newGCSSink(ctx context.Context, c Config) (Sink, error) {
	if c.Bucket == "" {
		return nil, fmt.Errorf("evidence sink: a gcs sink needs a bucket")
	}
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("evidence sink: build GCS client: %w", err)
	}
	return &gcsSink{client: client, bucket: c.Bucket, prefix: c.Prefix}, nil
}

func (s *gcsSink) Name() string { return TypeGCS }

func (s *gcsSink) Write(ctx context.Context, a Artifact) (string, error) {
	bucket := s.client.Bucket(s.bucket)
	for _, fileName := range a.FileNames() {
		key := objectKey(s.prefix, a.Run, fileName)
		w := bucket.Object(key).NewWriter(ctx)
		w.ContentType = contentType(fileName)
		w.Metadata = a.Annotations
		if _, err := w.Write(a.Files[fileName]); err != nil {
			// Close reports the real error for a failed upload, but the object
			// must be abandoned either way.
			_ = w.Close()
			return "", fmt.Errorf("write gs://%s/%s: %w", s.bucket, key, err)
		}
		if err := w.Close(); err != nil {
			return "", fmt.Errorf("finish gs://%s/%s: %w", s.bucket, key, err)
		}
	}
	return fmt.Sprintf("gs://%s/%s", s.bucket, objectKey(s.prefix, a.Run, "")), nil
}
