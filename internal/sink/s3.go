package sink

import (
	"bytes"
	"context"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3Sink writes one object per evidence file under <prefix>/<run>/.
//
// Credentials come from the ambient AWS chain, so in-cluster the recommended
// setup is IRSA or Pod Identity: the controller gets a short-lived role rather
// than a static key, which matches how it signs (keyless over workload identity)
// rather than undermining it.
type s3Sink struct {
	client *s3.Client
	bucket string
	prefix string
}

func newS3Sink(ctx context.Context, c Config) (Sink, error) {
	if c.Bucket == "" {
		return nil, fmt.Errorf("evidence sink: an s3 sink needs a bucket")
	}
	opts := []func(*awsconfig.LoadOptions) error{}
	if c.Region != "" {
		opts = append(opts, awsconfig.WithRegion(c.Region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("evidence sink: load AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("evidence sink: no AWS region configured; set the sink's region or AWS_REGION")
	}
	return &s3Sink{client: s3.NewFromConfig(cfg), bucket: c.Bucket, prefix: c.Prefix}, nil
}

func (s *s3Sink) Name() string { return TypeS3 }

func (s *s3Sink) Write(ctx context.Context, a Artifact) (string, error) {
	for _, fileName := range a.FileNames() {
		key := objectKey(s.prefix, a.Run, fileName)
		body := a.Files[fileName]
		_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:      &s.bucket,
			Key:         &key,
			Body:        bytes.NewReader(body),
			ContentType: contentTypePtr(fileName),
			Metadata:    a.Annotations,
		})
		if err != nil {
			return "", fmt.Errorf("put s3://%s/%s: %w", s.bucket, key, err)
		}
	}
	return fmt.Sprintf("s3://%s/%s", s.bucket, objectKey(s.prefix, a.Run, "")), nil
}
