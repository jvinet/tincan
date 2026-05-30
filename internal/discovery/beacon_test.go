package discovery

import (
	"strings"
	"testing"
)

func TestBeaconEncodeDecodeRoundTrip(t *testing.T) {
	in := Beacon{
		V:         1,
		PublicKey: "abcdefghABCDEFGH12345678abcdefghABCDEFGH1234",
		Port:      51820,
		Nonce:     0xdeadbeefcafebabe,
	}
	data, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch: got %+v want %+v", out, in)
	}
}

func TestEncodeFillsSchemaVersion(t *testing.T) {
	in := Beacon{
		PublicKey: "k",
		Port:      1,
	}
	data, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if out.V != BeaconSchemaVersion {
		t.Fatalf("V = %d, want %d", out.V, BeaconSchemaVersion)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"empty input", []byte{}, "decode beacon"},
		{"garbage", []byte{0xff, 0xff, 0xff}, "decode beacon"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.data); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestDecodeRequiresFields(t *testing.T) {
	cases := []struct {
		name string
		in   Beacon
		want string
	}{
		{"missing V", Beacon{V: 0, PublicKey: "k", Port: 1, Nonce: 1}, "schema version"},
		{"missing pubkey", Beacon{V: 1, PublicKey: "", Port: 1, Nonce: 1}, "public_key"},
		{"missing port", Beacon{V: 1, PublicKey: "k", Port: 0, Nonce: 1}, "port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use msgpack directly so we can encode beacons that Encode() would auto-fill.
			data := marshalRaw(t, tc.in)
			if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestDecodeIgnoresUnknownFields(t *testing.T) {
	type extended struct {
		V         uint32 `msgpack:"v"`
		PublicKey string `msgpack:"pk"`
		Port      uint16 `msgpack:"port"`
		Nonce     uint64 `msgpack:"n"`
		Future    string `msgpack:"x"`
	}
	ext := extended{V: 2, PublicKey: "k", Port: 51820, Nonce: 42, Future: "ignored"}
	data := marshalRaw(t, ext)
	out, err := Decode(data)
	if err != nil {
		t.Fatalf("forward-compat decode failed: %v", err)
	}
	if out.V != 2 || out.PublicKey != "k" || out.Port != 51820 || out.Nonce != 42 {
		t.Fatalf("decoded %+v", out)
	}
}
