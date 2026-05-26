package fakedrop

import (
	"context"
	"sync"
	"time"

	"github.com/jvinet/tincan/internal/drop"
)

type Drop struct {
	mu     sync.Mutex
	Data   []byte
	GetErr error
	PutErr error
}

func (d *Drop) Name() string { return "fake" }

func (d *Drop) Get(context.Context) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.GetErr != nil {
		return nil, d.GetErr
	}
	if d.Data == nil {
		return nil, drop.ErrNotFound
	}
	data := make([]byte, len(d.Data))
	copy(data, d.Data)
	return data, nil
}

func (d *Drop) Put(_ context.Context, data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.PutErr != nil {
		return d.PutErr
	}
	d.Data = append(d.Data[:0], data...)
	return nil
}

func (d *Drop) Stat(context.Context) (drop.Metadata, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Data == nil {
		return drop.Metadata{}, drop.ErrNotFound
	}
	return drop.Metadata{Size: int64(len(d.Data)), UpdatedAt: time.Now().UTC()}, nil
}
