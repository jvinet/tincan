package directory

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jvinet/tincan/internal/keys"
	"github.com/vmihailenco/msgpack/v5"
)

// sampleDirectory returns a two-node directory and alice's age identity (the
// secret that decrypts a blob sealed to this directory). Both members carry a
// real age recipient so Seal has someone to encrypt to.
func sampleDirectory(t *testing.T) (Directory, string) {
	t.Helper()
	_, alicePub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, bobPub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	aliceID, aliceRcpt, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, bobRcpt, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dir := Directory{
		SchemaVersion: SchemaVersion,
		Serial:        7,
		CreatedAt:     time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC),
		NetworkCIDR:   "10.42.0.0/24",
		Nodes: []Node{
			{Name: "alice", PublicKey: alicePub, TunnelIP: "10.42.0.1", AgeRecipient: aliceRcpt, Endpoint: "alice.example.com:51820"},
			{Name: "bob", PublicKey: bobPub, TunnelIP: "10.42.0.2", AgeRecipient: bobRcpt, ObservedEndpoint: "203.0.113.7:41234", ObservedAt: time.Date(2026, 5, 25, 9, 59, 0, 0, time.UTC)},
		},
	}
	return dir, aliceID
}

func cloneDirectory(dir Directory) Directory {
	out := dir
	out.Nodes = append([]Node(nil), dir.Nodes...)
	return out
}

func TestSealOpenRoundTrip(t *testing.T) {
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dir, identity := sampleDirectory(t)

	blob, err := Seal(dir, publisherPriv)
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

// Every member's identity must decrypt the same sealed blob, and a non-member
// identity must not — the foundation of per-node revocation.
func TestSealEncryptsToEveryRecipient(t *testing.T) {
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	aliceID, aliceRcpt, _ := keys.GenerateAgeIdentity()
	bobID, bobRcpt, _ := keys.GenerateAgeIdentity()
	_, aPub, _ := keys.GenerateWGKeypair()
	_, bPub, _ := keys.GenerateWGKeypair()
	dir := Directory{
		SchemaVersion: SchemaVersion, Serial: 3, CreatedAt: Stamp(), NetworkCIDR: "10.42.0.0/24",
		Nodes: []Node{
			{Name: "alice", PublicKey: aPub, TunnelIP: "10.42.0.1", AgeRecipient: aliceRcpt},
			{Name: "bob", PublicKey: bPub, TunnelIP: "10.42.0.2", AgeRecipient: bobRcpt},
		},
	}
	blob, err := Seal(dir, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{aliceID, bobID} {
		if _, _, err := Open(blob, id, publisherPub); err != nil {
			t.Fatalf("a member could not open the directory: %v", err)
		}
	}
	stranger, _, _ := keys.GenerateAgeIdentity()
	if _, _, err := Open(blob, stranger, publisherPub); err == nil {
		t.Fatal("a non-recipient identity opened the directory")
	}
}

// Removing a node and re-sealing revokes it: the removed node's identity can
// still open the old blob but not the new one, while a retained node opens
// both. This is the whole point of per-node recipients.
func TestRemovalRevokesDecryption(t *testing.T) {
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	aliceID, aliceRcpt, _ := keys.GenerateAgeIdentity()
	bobID, bobRcpt, _ := keys.GenerateAgeIdentity()
	_, aPub, _ := keys.GenerateWGKeypair()
	_, bPub, _ := keys.GenerateWGKeypair()
	dir := Directory{
		SchemaVersion: SchemaVersion, Serial: 3, CreatedAt: Stamp(), NetworkCIDR: "10.42.0.0/24",
		Nodes: []Node{
			{Name: "alice", PublicKey: aPub, TunnelIP: "10.42.0.1", AgeRecipient: aliceRcpt},
			{Name: "bob", PublicKey: bPub, TunnelIP: "10.42.0.2", AgeRecipient: bobRcpt},
		},
	}
	before, err := Seal(dir, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}
	// Drop bob and re-seal to the remaining recipients.
	revoked := cloneDirectory(dir)
	revoked.Nodes = revoked.Nodes[:1]
	revoked.Serial++
	after, err := Seal(revoked, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}
	// Bob can still open the blob he was a recipient of, but not the new one.
	if _, _, err := Open(before, bobID, publisherPub); err != nil {
		t.Fatalf("bob could not open the pre-removal blob he was a recipient of: %v", err)
	}
	if _, _, err := Open(after, bobID, publisherPub); err == nil {
		t.Fatal("revoked node still decrypted the post-removal directory")
	}
	// Alice (retained) opens both.
	if _, _, err := Open(before, aliceID, publisherPub); err != nil {
		t.Fatalf("alice could not open the pre-removal blob: %v", err)
	}
	if _, _, err := Open(after, aliceID, publisherPub); err != nil {
		t.Fatalf("alice could not open the post-removal blob: %v", err)
	}
}

func TestOpenRejectsWrongIdentity(t *testing.T) {
	wrongIdentity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := sampleDirectory(t)
	blob, err := Seal(dir, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := Open(blob, wrongIdentity, publisherPub); err == nil {
		t.Fatal("expected wrong age identity to fail")
	}
}

func TestOpenRejectsWrongPublisher(t *testing.T) {
	_, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	wrongPublisherPub, _, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dir, identity := sampleDirectory(t)
	blob, err := Seal(dir, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Open(blob, identity, wrongPublisherPub)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature error, got %v", err)
	}
}

func TestOpenRejectsTamperedBlob(t *testing.T) {
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dir, identity := sampleDirectory(t)
	blob, err := Seal(dir, publisherPriv)
	if err != nil {
		t.Fatal(err)
	}

	blob[len(blob)-1] ^= 0xff
	if _, _, err := Open(blob, identity, publisherPub); err == nil {
		t.Fatal("tampered blob unexpectedly verified")
	}
}

// The publisher signs a domain-separated message (signingDomain || payload),
// not the bare payload. A signature over just the payload — what a key reused
// in another context, or a pre-domain-separation tincan, would produce — must
// be rejected. This guards the domain tag against being silently dropped.
func TestSignatureIsDomainSeparated(t *testing.T) {
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dir, identity := sampleDirectory(t)
	payload, err := MarshalPlain(dir)
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := keys.DecodeEd25519Private(publisherPriv)
	if err != nil {
		t.Fatal(err)
	}
	// Sign the bare payload, omitting the domain prefix Seal would prepend.
	envBytes, err := msgpack.Marshal(Envelope{Payload: payload, Signature: ed25519.Sign(signKey, payload)})
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.ParseAgeIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(envBytes); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(encrypted.Bytes(), identity, publisherPub); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected an undomained signature to be rejected, got %v", err)
	}
}

func TestOpenRejectsOversizedBlob(t *testing.T) {
	identity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publisherPub, _, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, MaxBlobSize+1)
	_, _, err = Open(blob, identity, publisherPub)
	if err == nil || !strings.Contains(err.Error(), "max") {
		t.Fatalf("expected size error, got %v", err)
	}
}

// The envelope is decoded before signature verification, so unknown fields
// must be rejected rather than skipped (skipping recurses unboundedly on
// attacker-shaped plaintext). Envelope schema evolution belongs inside the
// signed payload.
func TestOpenRejectsUnknownEnvelopeFields(t *testing.T) {
	identity, _, err := keys.GenerateAgeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publisherPub, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := sampleDirectory(t)
	payload, err := MarshalPlain(dir)
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := keys.DecodeEd25519Private(publisherPriv)
	if err != nil {
		t.Fatal(err)
	}
	extended := struct {
		Payload   []byte `msgpack:"p"`
		Signature []byte `msgpack:"sig"`
		Extra     []byte `msgpack:"x"`
	}{payload, ed25519.Sign(signKey, payload), []byte("future")}
	envBytes, err := msgpack.Marshal(extended)
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.ParseAgeIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(envBytes); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	_, _, err = Open(encrypted.Bytes(), identity, publisherPub)
	if err == nil || !strings.Contains(err.Error(), "envelope") {
		t.Fatalf("expected envelope decode error, got %v", err)
	}
}

func TestSealRejectsInvalidDirectory(t *testing.T) {
	_, publisherPriv, err := keys.GenerateEd25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := sampleDirectory(t)
	dir.NetworkCIDR = "not-a-cidr"

	if _, err := Seal(dir, publisherPriv); err == nil {
		t.Fatal("expected invalid directory to fail sealing")
	}
}

func TestStampIsSecondPrecisionUTC(t *testing.T) {
	s := Stamp()
	if s.Nanosecond() != 0 {
		t.Fatalf("Stamp() has sub-second precision: %d ns", s.Nanosecond())
	}
	if s.Location() != time.UTC {
		t.Fatalf("Stamp() not UTC: %s", s.Location())
	}
}

func TestMarshalPlainDefaultsToSecondPrecision(t *testing.T) {
	dir, _ := sampleDirectory(t)
	dir.CreatedAt = time.Time{} // force the IsZero default-stamp path
	blob, err := MarshalPlain(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalPlain(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("CreatedAt was not stamped")
	}
	if got.CreatedAt.Nanosecond() != 0 {
		t.Fatalf("stamped CreatedAt has sub-second precision: %d ns", got.CreatedAt.Nanosecond())
	}
}

func TestMarshalPlainTimestampIsCompact(t *testing.T) {
	dir, _ := sampleDirectory(t) // CreatedAt is already whole-second
	whole, err := MarshalPlain(dir)
	if err != nil {
		t.Fatal(err)
	}
	sub := cloneDirectory(dir)
	sub.CreatedAt = sub.CreatedAt.Add(time.Nanosecond)
	subBlob, err := MarshalPlain(sub)
	if err != nil {
		t.Fatal(err)
	}
	// msgpack stores a whole-second time.Time as a 6-byte timestamp32 extension
	// and a sub-second one as a 10-byte timestamp64. That 4-byte gap is the
	// saving Stamp() keeps CreatedAt/ObservedAt at; guard it against a msgpack
	// change or a dropped Truncate.
	if delta := len(subBlob) - len(whole); delta != 4 {
		t.Fatalf("expected whole-second timestamp to save 4 bytes, got delta %d (%d vs %d)", delta, len(whole), len(subBlob))
	}
}

func TestNodeWireRoundTrip(t *testing.T) {
	_, pub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, psk, err := keys.GenerateWGKeypair() // a PSK is also a 32-byte WG key
	if err != nil {
		t.Fatal(err)
	}
	cases := []Node{
		{Name: "minimal", PublicKey: pub, TunnelIP: "10.42.0.9"},
		{Name: "full", PublicKey: pub, TunnelIP: "10.42.0.250",
			Endpoint: "host.example:51820", Relay: true, ObservedEndpoint: "203.0.113.7:7000",
			ObservedAt: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC), PSK: psk},
	}
	for _, want := range cases {
		t.Run(want.Name, func(t *testing.T) {
			w, err := want.toWire()
			if err != nil {
				t.Fatal(err)
			}
			var got Node
			if err := got.fromWire(w); err != nil {
				t.Fatal(err)
			}
			if got != want { // pure struct copy, so exact equality (incl. ObservedAt) holds
				t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestNodeEncodedAsRawBytes(t *testing.T) {
	dir, _ := sampleDirectory(t)
	payload, err := MarshalPlain(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range dir.Nodes {
		raw, err := keys.WGKeyToBytes(n.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(payload, raw) {
			t.Fatalf("node %q raw public key not found in payload", n.Name)
		}
		if bytes.Contains(payload, []byte(n.PublicKey)) {
			t.Fatalf("node %q base64 public key leaked into payload (not stored raw)", n.Name)
		}
	}
}

func TestFromWireRejectsMalformed(t *testing.T) {
	_, pub, err := keys.GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := keys.WGKeyToBytes(pub)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		w    wireNode
	}{
		{name: "short ip", w: wireNode{Name: "n", PublicKey: rawKey, TunnelIP: []byte{10, 42, 0}}},
		{name: "short key", w: wireNode{Name: "n", PublicKey: []byte{1, 2, 3}, TunnelIP: []byte{10, 42, 0, 1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var n Node
			if err := n.fromWire(tc.w); err == nil {
				t.Fatal("expected decode error, got nil")
			}
		})
	}
}

func TestValidateRejectsBadDirectories(t *testing.T) {
	valid, _ := sampleDirectory(t)
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
		{name: "endpoint missing port", mutate: func(d *Directory) { d.Nodes[0].Endpoint = "host.example.com" }},
		{name: "endpoint bad port", mutate: func(d *Directory) { d.Nodes[0].Endpoint = "host.example.com:99999" }},
		{name: "endpoint newline injection", mutate: func(d *Directory) { d.Nodes[0].Endpoint = "host:51820\nPostUp = evil" }},
		{name: "observed endpoint malformed", mutate: func(d *Directory) { d.Nodes[1].ObservedEndpoint = "garbage" }},
		{name: "bad age recipient", mutate: func(d *Directory) { d.Nodes[0].AgeRecipient = "age1notreal" }},
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
