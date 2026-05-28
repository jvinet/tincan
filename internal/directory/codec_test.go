package directory

import (
	"strings"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/keys"
)

func sampleDirectory(t *testing.T) Directory {
	t.Helper()
	_, alicePub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, bobPub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return Directory{
		SchemaVersion: SchemaVersion,
		Serial:        7,
		CreatedAt:     time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC),
		NetworkCIDR:   "10.42.0.0/24",
		Nodes: []Node{
			{Name: "alice", PublicKey: alicePub, TunnelIP: "10.42.0.1", Endpoint: "alice.example.com:51820"},
			{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2", ObservedEndpoint: "203.0.113.7:41234", ObservedAt: time.Date(2026, 5, 25, 9, 59, 0, 0, time.UTC)},
		},
	}
}

func cloneDirectory(dir Directory) Directory {
	out := dir
	out.Nodes = append([]Node(nil), dir.Nodes...)
	return out
}

func TestSealOpenRoundTrip(t *testing.T) {
	identity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dir := sampleDirectory(t)

	blob, err := Seal(dir, identity, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) == 0 {
		t.Fatal("empty encrypted blob")
	}
	opened, payload, err := Open(blob, identity, publisherPub)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Serial != dir.Serial || opened.NetworkCIDR != dir.NetworkCIDR || len(opened.Nodes) != len(dir.Nodes) || len(payload) == 0 {
		t.Fatalf("unexpected opened directory: %+v payload=%d", opened, len(payload))
	}
	if !opened.CreatedAt.Equal(dir.CreatedAt) {
		t.Fatalf("CreatedAt mismatch: got %s want %s", opened.CreatedAt, dir.CreatedAt)
	}
	for i := range dir.Nodes {
		want := dir.Nodes[i]
		got := opened.Nodes[i]
		if !got.ObservedAt.Equal(want.ObservedAt) {
			t.Fatalf("node %d ObservedAt mismatch: got %s want %s", i, got.ObservedAt, want.ObservedAt)
		}
		got.ObservedAt = want.ObservedAt
		if got != want {
			t.Fatalf("node %d mismatch: got %+v want %+v", i, opened.Nodes[i], dir.Nodes[i])
		}
	}
}

func TestOpenRejectsWrongIdentity(t *testing.T) {
	identity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrongIdentity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(sampleDirectory(t), identity, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := Open(blob, wrongIdentity, publisherPub); err == nil {
		t.Fatal("expected wrong age identity to fail")
	}
}

func TestOpenRejectsWrongPublisher(t *testing.T) {
	identity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	wrongPublisherPub, _, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(sampleDirectory(t), identity, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Open(blob, identity, wrongPublisherPub)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature error, got %v", err)
	}
}

func TestOpenRejectsTamperedBlob(t *testing.T) {
	identity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Seal(sampleDirectory(t), identity, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}

	blob[len(blob)-1] ^= 0xff
	if _, _, err := Open(blob, identity, publisherPub); err == nil {
		t.Fatal("tampered blob unexpectedly verified")
	}
}

func TestSealRejectsInvalidDirectory(t *testing.T) {
	identity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dir := sampleDirectory(t)
	dir.NetworkCIDR = "not-a-cidr"

	if _, err := Seal(dir, identity, publisherPriv); err == nil {
		t.Fatal("expected invalid directory to fail sealing")
	}
}

func TestValidateRejectsBadDirectories(t *testing.T) {
	valid := sampleDirectory(t)
	cases := []struct {
		name   string
		mutate func(*Directory)
	}{
		{name: "bad schema", mutate: func(d *Directory) { d.SchemaVersion = 99 }},
		{name: "bad CIDR", mutate: func(d *Directory) { d.NetworkCIDR = "bad" }},
		{name: "empty node name", mutate: func(d *Directory) { d.Nodes[0].Name = "" }},
		{name: "duplicate name", mutate: func(d *Directory) { d.Nodes[1].Name = d.Nodes[0].Name }},
		{name: "invalid public key", mutate: func(d *Directory) { d.Nodes[0].PublicKey = "not a key" }},
		{name: "duplicate public key", mutate: func(d *Directory) { d.Nodes[1].PublicKey = d.Nodes[0].PublicKey }},
		{name: "invalid tunnel IP", mutate: func(d *Directory) { d.Nodes[0].TunnelIP = "not an ip" }},
		{name: "IPv6 tunnel IP", mutate: func(d *Directory) { d.Nodes[0].TunnelIP = "fd00::1" }},
		{name: "outside CIDR", mutate: func(d *Directory) { d.Nodes[0].TunnelIP = "10.43.0.1" }},
		{name: "duplicate tunnel IP", mutate: func(d *Directory) { d.Nodes[1].TunnelIP = d.Nodes[0].TunnelIP }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := cloneDirectory(valid)
			tc.mutate(&dir)
			if err := Validate(dir); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
