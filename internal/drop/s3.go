package drop

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/jvinet/tincan/internal/config"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3 struct {
	client *minio.Client
	bucket string
	object string
	name   string
}

func NewS3(cfg config.DropBackend) (*S3, error) {
	creds := credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  creds,
		Region: cfg.Region,
		Secure: cfg.S3Secure(),
	})
	if err != nil {
		return nil, fmt.Errorf("create S3 client: %w", err)
	}
	return &S3{client: client, bucket: cfg.Bucket, object: cfg.ObjectKey, name: "s3:" + cfg.Bucket + "/" + cfg.ObjectKey}, nil
}

func (s *S3) Name() string { return s.name }

func (s *S3) Get(ctx context.Context) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, s.object, minio.GetObjectOptions{})
	if err != nil {
		return nil, mapS3Err(err)
	}
	defer obj.Close()
	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, mapS3Err(err)
	}
	return data, nil
}

func (s *S3) Put(ctx context.Context, data []byte) error {
	_, err := s.client.PutObject(ctx, s.bucket, s.object, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: "application/octet-stream"})
	return mapS3Err(err)
}

func (s *S3) Stat(ctx context.Context) (Metadata, error) {
	info, err := s.client.StatObject(ctx, s.bucket, s.object, minio.StatObjectOptions{})
	if err != nil {
		return Metadata{}, mapS3Err(err)
	}
	return Metadata{Size: info.Size, UpdatedAt: info.LastModified, ETag: info.ETag}, nil
}

func mapS3Err(err error) error {
	if err == nil {
		return nil
	}
	resp := minio.ToErrorResponse(err)
	switch resp.StatusCode {
	case 0:
		return err
	case 401, 403:
		return ErrAuth
	case 404:
		return ErrNotFound
	default:
		return err
	}
}
