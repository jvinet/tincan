package cli

import (
	"testing"
	"time"
)

func TestPeerLabelPrefersName(t *testing.T) {
	cases := []struct {
		name string
		peer statusPeer
		want string
	}{
		{
			name: "name set",
			peer: statusPeer{PublicKey: "abcdefghijklmnopqrstuvwxyz", Name: "bob"},
			want: "bob",
		},
		{
			name: "long pubkey, no name",
			peer: statusPeer{PublicKey: "abcdefghijklmnopqrstuvwxyz"},
			want: "abcdefgh…",
		},
		{
			name: "short pubkey, no name",
			peer: statusPeer{PublicKey: "abcdef"},
			want: "abcdef",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerLabel(tc.peer); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestPeerEndpointLabelPriority(t *testing.T) {
	observedAt := time.Now().Add(-2 * time.Minute)

	cases := []struct {
		name     string
		peer     statusPeer
		contains string
		exact    string
	}{
		{
			name:  "wgctrl wins",
			peer:  statusPeer{Endpoint: "10.0.0.1:51820", DirectoryEndpoint: "ignored", ObservedEndpoint: "203.0.113.7:5555"},
			exact: "10.0.0.1:51820",
		},
		{
			name:  "directory configured shown when wgctrl missing",
			peer:  statusPeer{DirectoryEndpoint: "alice.example.com:51820"},
			exact: "alice.example.com:51820 (configured)",
		},
		{
			name:     "observed shown with age when only observation",
			peer:     statusPeer{ObservedEndpoint: "203.0.113.7:5555", ObservedAt: &observedAt},
			contains: "203.0.113.7:5555 (observed ",
		},
		{
			name:  "observed shown without age when no timestamp",
			peer:  statusPeer{ObservedEndpoint: "203.0.113.7:5555"},
			exact: "203.0.113.7:5555 (observed)",
		},
		{
			name:  "dash when nothing known",
			peer:  statusPeer{},
			exact: "-",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := peerEndpointLabel(tc.peer)
			if tc.exact != "" && got != tc.exact {
				t.Fatalf("got %q want %q", got, tc.exact)
			}
			if tc.contains != "" && !startsWith(got, tc.contains) {
				t.Fatalf("got %q want prefix %q", got, tc.contains)
			}
		})
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
