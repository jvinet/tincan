package directory

import "testing"

func TestRelayTarget(t *testing.T) {
	node := func(name, pubkey, endpoint string, relay bool) Node {
		return Node{Name: name, PublicKey: pubkey, Endpoint: endpoint, Relay: relay}
	}
	cases := []struct {
		name     string
		nodes    []Node
		self     string
		wantName string
		wantOK   bool
	}{
		{
			name:   "no endpoints",
			nodes:  []Node{node("a", "ka", "", false), node("b", "kb", "", false)},
			self:   "ka",
			wantOK: false,
		},
		{
			name:     "falls back to first node with an endpoint",
			nodes:    []Node{node("a", "ka", "", false), node("b", "kb", "b:51820", false), node("c", "kc", "c:51820", false)},
			self:     "ka",
			wantName: "b",
			wantOK:   true,
		},
		{
			name:     "prefers a marked relay over an earlier endpoint node",
			nodes:    []Node{node("a", "ka", "a:51820", false), node("b", "kb", "b:51820", true)},
			self:     "kself",
			wantName: "b",
			wantOK:   true,
		},
		{
			name:     "ignores a relay flag with no endpoint, uses the endpoint fallback",
			nodes:    []Node{node("flagged", "kf", "", true), node("reachable", "kr", "r:51820", false)},
			self:     "kself",
			wantName: "reachable",
			wantOK:   true,
		},
		{
			name:     "never selects self even when self is the only relay",
			nodes:    []Node{node("self", "kself", "self:51820", true), node("peer", "kp", "p:51820", false)},
			self:     "kself",
			wantName: "peer",
			wantOK:   true,
		},
		{
			name:     "empty self considers every node (plain-WireGuard hub pick)",
			nodes:    []Node{node("hub", "kh", "h:51820", true), node("other", "ko", "o:51820", false)},
			self:     "",
			wantName: "hub",
			wantOK:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := RelayTarget(Directory{Nodes: tc.nodes}, tc.self)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got.Name != tc.wantName {
				t.Fatalf("selected %q, want %q", got.Name, tc.wantName)
			}
		})
	}
}
