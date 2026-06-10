package discovery

import (
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
)

// fakeGroupConn records membership operations in order. LeaveGroup always
// errors, mimicking a leave of a group that was never joined — which
// rejoinGroups must tolerate, since that is the steady state for a brand
// new interface.
type fakeGroupConn struct {
	ops      []string
	failJoin map[string]bool
}

func (f *fakeGroupConn) JoinGroup(ifi *net.Interface, _ net.Addr) error {
	if f.failJoin[ifi.Name] {
		return errors.New("join refused")
	}
	f.ops = append(f.ops, "join "+ifi.Name)
	return nil
}

func (f *fakeGroupConn) LeaveGroup(ifi *net.Interface, _ net.Addr) error {
	f.ops = append(f.ops, "leave "+ifi.Name)
	return errors.New("not joined")
}

func TestRejoinGroupsLeavesThenJoinsEachInterface(t *testing.T) {
	conn := &fakeGroupConn{}
	ifaces := []net.Interface{
		{Index: 1, Name: "eth0"},
		{Index: 2, Name: "wlan0"},
	}
	group := &net.UDPAddr{IP: net.ParseIP("239.255.84.67")}

	if got := rejoinGroups(conn, group, ifaces, "IPv4"); got != 2 {
		t.Fatalf("joined=%d want 2", got)
	}
	// Leave must precede join per interface: a join on an already-joined
	// group is a kernel refcount no-op and would not re-announce IGMP/MLD
	// membership to snooping switches.
	want := []string{"leave eth0", "join eth0", "leave wlan0", "join wlan0"}
	if !slices.Equal(conn.ops, want) {
		t.Fatalf("ops=%v want %v", conn.ops, want)
	}
}

func TestRejoinGroupsSkipsFailedJoinAndContinues(t *testing.T) {
	conn := &fakeGroupConn{failJoin: map[string]bool{"eth0": true}}
	ifaces := []net.Interface{
		{Index: 1, Name: "eth0"},
		{Index: 2, Name: "wlan0"},
	}
	group := &net.UDPAddr{IP: net.ParseIP("239.255.84.67")}

	if got := rejoinGroups(conn, group, ifaces, "IPv4"); got != 1 {
		t.Fatalf("joined=%d want 1", got)
	}
	want := []string{"leave eth0", "leave wlan0", "join wlan0"}
	if !slices.Equal(conn.ops, want) {
		t.Fatalf("ops=%v want %v", conn.ops, want)
	}
}

func TestRejoinGroupsNoInterfaces(t *testing.T) {
	conn := &fakeGroupConn{}
	group := &net.UDPAddr{IP: net.ParseIP("239.255.84.67")}
	if got := rejoinGroups(conn, group, nil, "IPv4"); got != 0 {
		t.Fatalf("joined=%d want 0", got)
	}
	if len(conn.ops) != 0 {
		t.Fatalf("ops=%v want none", conn.ops)
	}
}

// --- processBeacon ingress filtering ---

const tunnelIfIndex = 7

// testFilter mimics a host where ifindex 7 is the Tincan interface and
// everything else is a LAN NIC.
func testFilter() beaconFilter {
	return beaconFilter{
		group:     net.ParseIP("239.255.84.67"),
		skipIface: "tincan0",
		ifaceName: func(index int) (string, error) {
			if index == tunnelIfIndex {
				return "tincan0", nil
			}
			return "eth0", nil
		},
	}
}

func testDirSource() DirectorySource {
	return func() directory.Directory {
		return directory.Directory{
			NetworkCIDR: "10.42.0.0/24",
			Nodes: []directory.Node{
				{Name: "bob", PublicKey: "BOBKEY", TunnelIP: "10.42.0.2"},
			},
		}
	}
}

func encodeBeacon(t *testing.T, pubkey string, port uint16) []byte {
	t.Helper()
	data, err := Encode(Beacon{PublicKey: pubkey, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func runProcessBeacon(t *testing.T, dst net.IP, ifIndex int, srcIP string) *Store {
	t.Helper()
	store := NewStore(90 * time.Second)
	src := &net.UDPAddr{IP: net.ParseIP(srcIP), Port: 51821}
	processBeacon(encodeBeacon(t, "BOBKEY", 51820), src, dst, ifIndex, testFilter(), store, testDirSource(), nil, nil)
	return store
}

func TestProcessBeaconAcceptsGroupAddressedLANBeacon(t *testing.T) {
	store := runProcessBeacon(t, net.ParseIP("239.255.84.67"), 3, "192.0.2.10")
	if got := store.Lookup("BOBKEY", time.Now()); got != "192.0.2.10:51820" {
		t.Fatalf("Lookup=%q want %q", got, "192.0.2.10:51820")
	}
}

func TestProcessBeaconDropsUnicastDestination(t *testing.T) {
	// A beacon delivered to our unicast address — e.g. sent over the WAN or
	// across the tunnel straight at the listen port — must never be learned.
	store := runProcessBeacon(t, net.ParseIP("192.0.2.1"), 3, "192.0.2.10")
	if got := store.LookupLastKnown("BOBKEY"); got != "" {
		t.Fatalf("unicast-addressed beacon was learned: %q", got)
	}
}

func TestProcessBeaconDropsWhenControlMessageMissing(t *testing.T) {
	store := runProcessBeacon(t, nil, 3, "192.0.2.10")
	if got := store.LookupLastKnown("BOBKEY"); got != "" {
		t.Fatalf("beacon without destination metadata was learned: %q", got)
	}
}

func TestProcessBeaconDropsTunnelIngress(t *testing.T) {
	// IP_MULTICAST_ALL delivers group traffic from interfaces we never
	// joined, including the tunnel; the ingress-interface check must drop it.
	store := runProcessBeacon(t, net.ParseIP("239.255.84.67"), tunnelIfIndex, "192.0.2.10")
	if got := store.LookupLastKnown("BOBKEY"); got != "" {
		t.Fatalf("tunnel-ingress beacon was learned: %q", got)
	}
}

func TestProcessBeaconDropsTunnelNetworkSource(t *testing.T) {
	store := runProcessBeacon(t, net.ParseIP("239.255.84.67"), 3, "10.42.0.3")
	if got := store.LookupLastKnown("BOBKEY"); got != "" {
		t.Fatalf("tunnel-sourced beacon was learned: %q", got)
	}
}
