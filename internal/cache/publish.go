package cache

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/google/renameio/v2"
	"github.com/jvinet/tincan/internal/config"
)

// ReadPublishSerial returns the highest locally reserved upload serial. This is
// separate from cache.serial: a failed upload must not prevent an admin from
// applying its last accepted cache while the drop is offline.
func ReadPublishSerial(stateDir string) (uint64, error) {
	return readSerial(config.PublishSerialPath(stateDir))
}

// ReservePublishSerial durably consumes a serial before upload, even if the
// upload later fails or its acknowledgment is lost. Local admin transactions
// hold LockAdmin; the state lock also makes the reservation itself atomic.
func ReservePublishSerial(stateDir string, serial uint64) error {
	return withStateLock(stateDir, func() error {
		previous, err := ReadPublishSerial(stateDir)
		switch {
		case err == nil:
			if serial <= previous {
				return fmt.Errorf("publish serial %d has already been reserved (floor %d)", serial, previous)
			}
		case errors.Is(err, os.ErrNotExist):
		default:
			return fmt.Errorf("read publish serial: %w", err)
		}
		data := []byte(strconv.FormatUint(serial, 10) + "\n")
		if err := renameio.WriteFile(config.PublishSerialPath(stateDir), data, 0o600); err != nil {
			return fmt.Errorf("reserve publish serial: %w", err)
		}
		return nil
	})
}
