package cache

import (
	"os"
	"testing"

	"github.com/jvinet/tincan/internal/config"
)

func TestPublishSerialReservationsAreStrictlyIncreasing(t *testing.T) {
	state := t.TempDir()
	for _, serial := range []uint64{2, 3} {
		if err := ReservePublishSerial(state, serial); err != nil {
			t.Fatal(err)
		}
	}
	for _, serial := range []uint64{2, 3} {
		if err := ReservePublishSerial(state, serial); err == nil {
			t.Fatalf("reserved an already consumed serial: %d", serial)
		}
	}
	floor, err := ReadPublishSerial(state)
	if err != nil || floor != 3 {
		t.Fatalf("floor = %d, err = %v", floor, err)
	}
	if _, err := ReadSerial(state); !os.IsNotExist(err) {
		t.Fatalf("reservation affected the accepted cache floor: %v", err)
	}
}

func TestPublishSerialReservationFailsClosed(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(config.PublishSerialPath(state), []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReservePublishSerial(state, 2); err == nil {
		t.Fatal("corrupt reservation silently reset")
	}
}
