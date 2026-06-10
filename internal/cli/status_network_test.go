package cli

import (
	"testing"
	"time"
)

func TestNetworkRoleLabel(t *testing.T) {
	cases := []struct {
		name string
		node networkNode
		want string
	}{
		{"plain", networkNode{}, "-"},
		{"relay", networkNode{Relay: true}, "relay"},
		{"self", networkNode{Self: true}, "self"},
		{"self relay", networkNode{Self: true, Relay: true}, "self,relay"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := networkRoleLabel(tc.node); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestNetworkEndpointLabel(t *testing.T) {
	cases := []struct {
		name string
		node networkNode
		want string
	}{
		{"none", networkNode{}, "-"},
		{"configured", networkNode{Endpoint: "host:51820", EndpointSource: "configured"}, "host:51820"},
		{"observed annotated", networkNode{Endpoint: "203.0.113.7:5555", EndpointSource: "observed"}, "203.0.113.7:5555 (observed)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := networkEndpointLabel(tc.node); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestNetworkHandshakeLabel(t *testing.T) {
	hs := time.Now().Add(-90 * time.Second)
	cases := []struct {
		name string
		node networkNode
		want string
	}{
		{"self", networkNode{Self: true}, "—"},
		{"no session", networkNode{HasSession: false}, "no session"},
		{"session never handshaked", networkNode{HasSession: true}, "never"},
		{"session with age", networkNode{HasSession: true, LastHandshake: &hs, LastHandshakeAge: "1m30s"}, "1m30s ago"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := networkHandshakeLabel(tc.node); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
