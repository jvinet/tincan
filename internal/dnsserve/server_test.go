package dnsserve

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jvinet/tincan/internal/directory"
	"golang.org/x/net/dns/dnsmessage"
)

func testDir() directory.Directory {
	return directory.Directory{
		Domain:      "vpn",
		NetworkCIDR: "10.42.0.0/24",
		Nodes: []directory.Node{
			{Name: "alice", TunnelIP: "10.42.0.1"},
			{Name: "NAS", TunnelIP: "10.42.0.3"},
		},
	}
}

func buildQuery(t *testing.T, id uint16, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type parsedReply struct {
	header    dnsmessage.Header
	question  *dnsmessage.Question
	answers   []dnsmessage.Resource
}

func parseReply(t *testing.T, reply []byte) parsedReply {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(reply)
	if err != nil {
		t.Fatalf("parse reply header: %v", err)
	}
	out := parsedReply{header: hdr}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatalf("parse reply questions: %v", err)
	}
	if len(qs) > 0 {
		out.question = &qs[0]
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatalf("parse reply answers: %v", err)
	}
	out.answers = answers
	return out
}

func TestRespondAnswersKnownName(t *testing.T) {
	// Mixed case both ways: the label matches case-insensitively, and the
	// question must be echoed with the client's original spelling (0x20).
	query := buildQuery(t, 0xbeef, "NaS.vpn.", dnsmessage.TypeA)
	reply, forward := respond(query, "vpn", testDir())
	if forward || reply == nil {
		t.Fatalf("forward=%v reply=%v", forward, reply)
	}
	got := parseReply(t, reply)
	if got.header.ID != 0xbeef || !got.header.Response || !got.header.Authoritative || !got.header.RecursionAvailable {
		t.Fatalf("bad header: %+v", got.header)
	}
	if got.header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v", got.header.RCode)
	}
	if got.question == nil || got.question.Name.String() != "NaS.vpn." {
		t.Fatalf("question not echoed with original case: %+v", got.question)
	}
	if len(got.answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(got.answers))
	}
	a, ok := got.answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer body %T, want A", got.answers[0].Body)
	}
	if ip := net.IP(a.A[:]).String(); ip != "10.42.0.3" {
		t.Fatalf("A = %s, want 10.42.0.3", ip)
	}
	if got.answers[0].Header.TTL != answerTTL {
		t.Fatalf("TTL = %d, want %d", got.answers[0].Header.TTL, answerTTL)
	}
}

func TestRespondRCodeMatrix(t *testing.T) {
	cases := []struct {
		name  string
		qname string
		qtype dnsmessage.Type
		rcode dnsmessage.RCode
	}{
		{name: "AAAA known name empty NOERROR", qname: "nas.vpn.", qtype: dnsmessage.TypeAAAA, rcode: dnsmessage.RCodeSuccess},
		{name: "HTTPS known name empty NOERROR", qname: "nas.vpn.", qtype: dnsmessage.Type(65), rcode: dnsmessage.RCodeSuccess},
		{name: "TXT known name empty NOERROR", qname: "alice.vpn.", qtype: dnsmessage.TypeTXT, rcode: dnsmessage.RCodeSuccess},
		{name: "unknown name NXDOMAIN", qname: "ghost.vpn.", qtype: dnsmessage.TypeA, rcode: dnsmessage.RCodeNameError},
		{name: "apex empty NOERROR", qname: "vpn.", qtype: dnsmessage.TypeA, rcode: dnsmessage.RCodeSuccess},
		{name: "multi-label NXDOMAIN", qname: "a.b.vpn.", qtype: dnsmessage.TypeA, rcode: dnsmessage.RCodeNameError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply, forward := respond(buildQuery(t, 1, tc.qname, tc.qtype), "vpn", testDir())
			if forward || reply == nil {
				t.Fatalf("forward=%v reply=%v", forward, reply)
			}
			got := parseReply(t, reply)
			if got.header.RCode != tc.rcode {
				t.Fatalf("rcode = %v, want %v", got.header.RCode, tc.rcode)
			}
			if len(got.answers) != 0 {
				t.Fatalf("answers = %d, want 0", len(got.answers))
			}
		})
	}
}

func TestRespondForwardsOutsideDomain(t *testing.T) {
	for _, qname := range []string{"example.com.", "vpnx.", "evil-vpn.", "nas.vpn.example.com."} {
		if _, forward := respond(buildQuery(t, 1, qname, dnsmessage.TypeA), "vpn", testDir()); !forward {
			t.Fatalf("%s not forwarded", qname)
		}
	}
}

func TestRespondPTR(t *testing.T) {
	// In-CIDR hit.
	reply, forward := respond(buildQuery(t, 1, "3.0.42.10.in-addr.arpa.", dnsmessage.TypePTR), "vpn", testDir())
	if forward || reply == nil {
		t.Fatalf("forward=%v", forward)
	}
	got := parseReply(t, reply)
	if len(got.answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(got.answers))
	}
	ptr, ok := got.answers[0].Body.(*dnsmessage.PTRResource)
	if !ok || ptr.PTR.String() != "nas.vpn." {
		t.Fatalf("PTR = %+v, want nas.vpn.", got.answers[0].Body)
	}

	// In-CIDR, unassigned: authoritative NXDOMAIN.
	reply, forward = respond(buildQuery(t, 1, "200.0.42.10.in-addr.arpa.", dnsmessage.TypePTR), "vpn", testDir())
	if forward {
		t.Fatal("unassigned in-CIDR PTR was forwarded")
	}
	if got := parseReply(t, reply); got.header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("rcode = %v, want NXDOMAIN", got.header.RCode)
	}

	// Outside the CIDR: the upstream's tree.
	if _, forward := respond(buildQuery(t, 1, "8.8.8.8.in-addr.arpa.", dnsmessage.TypePTR), "vpn", testDir()); !forward {
		t.Fatal("out-of-CIDR PTR not forwarded")
	}
	// IPv6 reverse: also the upstream's.
	if _, forward := respond(buildQuery(t, 1, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.", dnsmessage.TypePTR), "vpn", testDir()); !forward {
		t.Fatal("ip6.arpa not forwarded")
	}
}

func TestRespondHostilePackets(t *testing.T) {
	// Truncated header: drop.
	if reply, forward := respond([]byte{0x12, 0x34, 0x01}, "vpn", testDir()); reply != nil || forward {
		t.Fatal("truncated packet not dropped")
	}
	// A response (QR set): drop, never answer or forward (loop bait).
	resp := buildQuery(t, 7, "nas.vpn.", dnsmessage.TypeA)
	resp[2] |= qrBit
	if reply, forward := respond(resp, "vpn", testDir()); reply != nil || forward {
		t.Fatal("response packet not dropped")
	}
	// Header claims one question but the section is truncated: FORMERR.
	q := buildQuery(t, 9, "nas.vpn.", dnsmessage.TypeA)
	if reply, forward := respond(q[:headerLen+3], "vpn", testDir()); forward || reply == nil {
		t.Fatal("truncated question not answered with FORMERR")
	} else if got := parseReply(t, reply); got.header.RCode != dnsmessage.RCodeFormatError {
		t.Fatalf("rcode = %v, want FORMERR", got.header.RCode)
	}
}

func TestServfailFor(t *testing.T) {
	query := buildQuery(t, 0xabcd, "example.com.", dnsmessage.TypeA)
	out := servfailFor(query)
	got := parseReply(t, out)
	if !got.header.Response || got.header.RCode != dnsmessage.RCodeServerFailure || !got.header.RecursionAvailable {
		t.Fatalf("bad servfail header: %+v", got.header)
	}
	if got.header.ID != 0xabcd || got.question == nil || got.question.Name.String() != "example.com." {
		t.Fatalf("servfail does not echo the query: %+v", got)
	}
}

// startTestServer runs a server on loopback with a swappable directory and
// the given upstream address, returning a client socket aimed at it.
func startTestServer(t *testing.T, upstream string, timeout time.Duration) (*Server, *net.UDPConn, *atomic.Pointer[directory.Directory]) {
	t.Helper()
	var holder atomic.Pointer[directory.Directory]
	dir := testDir()
	holder.Store(&dir)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv, err := Start(ctx, Config{
		Addr:     "127.0.0.1:0",
		Domain:   "vpn",
		Upstream: upstream,
		Timeout:  timeout,
	}, func() directory.Directory { return *holder.Load() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	raddr, err := net.ResolveUDPAddr("udp", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return srv, client, &holder
}

func exchangeWith(t *testing.T, client *net.UDPConn, query []byte) []byte {
	t.Helper()
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestServerAnswersAndTracksDirectorySwap(t *testing.T) {
	_, client, holder := startTestServer(t, "127.0.0.1:1", 200*time.Millisecond)

	reply := exchangeWith(t, client, buildQuery(t, 21, "nas.vpn.", dnsmessage.TypeA))
	if got := parseReply(t, reply); got.header.RCode != dnsmessage.RCodeSuccess || len(got.answers) != 1 {
		t.Fatalf("unexpected reply: %+v", got)
	}

	// Swap in a snapshot without nas: answers must track it, no restart.
	smaller := testDir()
	smaller.Nodes = smaller.Nodes[:1]
	holder.Store(&smaller)
	reply = exchangeWith(t, client, buildQuery(t, 22, "nas.vpn.", dnsmessage.TypeA))
	if got := parseReply(t, reply); got.header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("rcode after swap = %v, want NXDOMAIN", got.header.RCode)
	}
}

func TestServerForwardsVerbatim(t *testing.T) {
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	canned := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := upstream.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Echo the query with QR set and a bogus extra byte payload to
			// prove the relay is byte-for-byte, not re-encoded.
			reply := append([]byte{}, buf[:n]...)
			reply[2] |= qrBit
			reply = append(reply, 0xfe)
			canned <- reply
			_, _ = upstream.WriteToUDP(reply, raddr)
		}
	}()

	_, client, _ := startTestServer(t, upstream.LocalAddr().String(), time.Second)
	got := exchangeWith(t, client, buildQuery(t, 31, "example.com.", dnsmessage.TypeA))
	want := <-canned
	if !bytes.Equal(got, want) {
		t.Fatalf("forwarded reply not relayed verbatim:\ngot  %x\nwant %x", got, want)
	}
}

func TestServerForwardTimeoutYieldsServfail(t *testing.T) {
	// Upstream that answers with the wrong ID, then goes silent: the server
	// must skip the mismatched reply and synthesize SERVFAIL at deadline.
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := upstream.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := append([]byte{}, buf[:n]...)
			reply[0] ^= 0xff // wrong ID
			reply[2] |= qrBit
			_, _ = upstream.WriteToUDP(reply, raddr)
		}
	}()

	_, client, _ := startTestServer(t, upstream.LocalAddr().String(), 300*time.Millisecond)
	reply := exchangeWith(t, client, buildQuery(t, 41, "example.com.", dnsmessage.TypeA))
	got := parseReply(t, reply)
	if got.header.RCode != dnsmessage.RCodeServerFailure || got.header.ID != 41 {
		t.Fatalf("expected SERVFAIL for id 41, got %+v", got.header)
	}
}

func TestStartRejectsSelfUpstream(t *testing.T) {
	_, err := Start(t.Context(), Config{Addr: "127.0.0.1:5391", Domain: "vpn", Upstream: "127.0.0.1:5391"}, testDir)
	if err == nil || !strings.Contains(err.Error(), "itself") {
		t.Fatalf("self-upstream not rejected: %v", err)
	}
}

func TestProbe(t *testing.T) {
	srv, _, _ := startTestServer(t, "127.0.0.1:1", 200*time.Millisecond)
	if !Probe(srv.LocalAddr().String(), "vpn", time.Second) {
		t.Fatal("Probe(live server) = false")
	}
	addr := srv.LocalAddr().String()
	_ = srv.Close()
	if Probe(addr, "vpn", 200*time.Millisecond) {
		t.Fatal("Probe(closed server) = true")
	}
}

func TestUpstreamFromResolvConf(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		path := filepath.Join(dir, "resolv.conf")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	got, err := upstreamFromResolvConf(write("# comment\nsearch lan\nnameserver 127.0.0.53\nnameserver 1.1.1.1\n"))
	if err != nil || got != "127.0.0.53:53" {
		t.Fatalf("got %q err=%v, want first nameserver", got, err)
	}
	if _, err := upstreamFromResolvConf(write("search lan\n")); err == nil {
		t.Fatal("expected error for resolv.conf without nameservers")
	}
	if _, err := upstreamFromResolvConf(write("nameserver not-an-ip\n")); err == nil {
		t.Fatal("expected error for unparsable nameserver")
	}
}
