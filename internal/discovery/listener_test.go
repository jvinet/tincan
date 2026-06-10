package discovery

import (
	"errors"
	"net"
	"slices"
	"testing"
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
