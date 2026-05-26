package drop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/renameio/v2"
)

type File struct {
	path string
}

func NewFile(path string) *File {
	return &File{path: path}
}

func (f *File) Name() string { return "file:" + f.path }

func (f *File) Get(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read file drop: %w", err)
	}
	return data, nil
}

func (f *File) Put(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return fmt.Errorf("create file drop directory: %w", err)
	}
	if err := renameio.WriteFile(f.path, data, 0o600); err != nil {
		return fmt.Errorf("write file drop: %w", err)
	}
	return nil
}

func (f *File) Stat(ctx context.Context) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	st, err := os.Stat(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return Metadata{}, ErrNotFound
	}
	if err != nil {
		return Metadata{}, fmt.Errorf("stat file drop: %w", err)
	}
	return Metadata{Size: st.Size(), UpdatedAt: st.ModTime()}, nil
}
