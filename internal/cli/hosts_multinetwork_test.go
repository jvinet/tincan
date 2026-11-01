package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/jvinet/tincan/internal/directory"
)

func TestHostsMultipleNetworksSyncStatusAndTeardown(t *testing.T) {
	cfg0, dir0, path := hostsSyncFixture(t)
	cfg1 := *cfg0
	cfg1.Wireguard.Interface = "tincan1"
	dir1 := directory.Directory{
		Domain: "home",
		Nodes:  []directory.Node{{Name: "alice", TunnelIP: "10.43.0.1"}},
	}
	var buf bytes.Buffer
	p := newPrinter(&buf)
	h := &hostsSyncer{}
	h.sync(cfg0, dir0, p)
	if got := dnsStatusFields(&cfg1, dir1, directory.Node{}); got["hosts_applied"] != false {
		t.Fatalf("other network's block should not satisfy status: %v", got)
	}
	h.sync(&cfg1, dir1, p)
	if got := dnsStatusFields(cfg0, dir0, directory.Node{}); got["hosts_applied"] != true {
		t.Fatalf("first network not applied: %v", got)
	}
	if got := dnsStatusFields(&cfg1, dir1, directory.Node{}); got["hosts_applied"] != true {
		t.Fatalf("second network not applied: %v", got)
	}
	// Clearing one network's domain leaves the other's block and status intact.
	dir0.Domain = ""
	h.sync(cfg0, dir0, p)
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "bob.vpn") || !strings.Contains(string(data), "alice.home") {
		t.Fatalf("domain clear affected wrong block: err=%v\n%s", err, data)
	}
	if got := dnsStatusFields(&cfg1, dir1, directory.Node{}); got["hosts_applied"] != true {
		t.Fatalf("second network status changed: %v", got)
	}
	// Re-add the first, then tear down the second.
	dir0.Domain = "vpn"
	h.sync(cfg0, dir0, p)
	removeHostsBlock(&cfg1, p)
	data, err = os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "alice.home") || !strings.Contains(string(data), "bob.vpn") {
		t.Fatalf("teardown affected wrong block: err=%v\n%s", err, data)
	}
}
