package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/renameio/v2"
	"github.com/jvinet/tincan/internal/config"
	"github.com/jvinet/tincan/internal/directory"
)

type State struct {
	LastSync time.Time `json:"last_sync"`
	LastETag string    `json:"last_etag,omitempty"`
	Serial   uint64    `json:"serial"`
}

func Read(cachePath string) (directory.Directory, []byte, error) {
	data, err := os.ReadFile(cachePath)
	if errors.Is(err, os.ErrNotExist) {
		return directory.Directory{}, nil, os.ErrNotExist
	}
	if err != nil {
		return directory.Directory{}, nil, fmt.Errorf("read cache: %w", err)
	}
	dir, err := directory.UnmarshalPlain(data)
	if err != nil {
		return directory.Directory{}, nil, err
	}
	return dir, data, nil
}

func Write(cachePath string, dir directory.Directory, etag string) error {
	payload, err := directory.MarshalPlain(dir)
	if err != nil {
		return err
	}
	if err := ensureDir(cachePath); err != nil {
		return err
	}
	if err := renameio.WriteFile(cachePath, payload, 0o600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	serial := strconv.FormatUint(dir.Serial, 10) + "\n"
	if err := renameio.WriteFile(config.SerialPath(cachePath), []byte(serial), 0o600); err != nil {
		return fmt.Errorf("write cache serial: %w", err)
	}
	state := State{LastSync: time.Now().UTC(), LastETag: etag, Serial: dir.Serial}
	stateBytes, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	stateBytes = append(stateBytes, '\n')
	if err := renameio.WriteFile(config.StatePath(cachePath), stateBytes, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

func ReadSerial(cachePath string) (uint64, error) {
	data, err := os.ReadFile(config.SerialPath(cachePath))
	if err != nil {
		return 0, err
	}
	serial, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse cache serial: %w", err)
	}
	return serial, nil
}

func ReadState(cachePath string) (State, error) {
	data, err := os.ReadFile(config.StatePath(cachePath))
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("decode state: %w", err)
	}
	return state, nil
}

func ReadSource(cachePath string) (directory.Directory, error) {
	data, err := os.ReadFile(config.SourcePath(cachePath))
	if err != nil {
		return directory.Directory{}, err
	}
	return directory.UnmarshalPlain(data)
}

func WriteSource(cachePath string, dir directory.Directory) error {
	payload, err := directory.MarshalPlain(dir)
	if err != nil {
		return err
	}
	if err := ensureDir(cachePath); err != nil {
		return err
	}
	if err := renameio.WriteFile(config.SourcePath(cachePath), payload, 0o600); err != nil {
		return fmt.Errorf("write source directory: %w", err)
	}
	return nil
}

func ensureDir(cachePath string) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	return nil
}
