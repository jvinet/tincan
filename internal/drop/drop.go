package drop

import (
	"context"
	"fmt"
	"time"

	"github.com/jvinet/tincan/internal/config"
)

type Metadata struct {
	Size      int64
	UpdatedAt time.Time
	ETag      string
}

type Drop interface {
	Get(ctx context.Context) ([]byte, error)
	Put(ctx context.Context, data []byte) error
	Stat(ctx context.Context) (Metadata, error)
	Name() string
}

func New(cfg config.DropBackend) (Drop, error) {
	switch cfg.Type {
	case "file":
		return NewFile(cfg.Path), nil
	case "http":
		return NewHTTP(cfg.URL, cfg.Username, cfg.Password), nil
	case "s3":
		return NewS3(cfg)
	case "dns":
		return NewDNS(cfg)
	default:
		return nil, fmt.Errorf("unsupported drop type %q", cfg.Type)
	}
}
