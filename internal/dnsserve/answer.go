package dnsserve

import (
	"net/netip"
	"strings"

	"github.com/jvinet/tincan/internal/directory"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	headerLen = 12   // fixed DNS header size
	qrBit     = 0x80 // QR flag in header byte 2
	// answerTTL keeps spoke caches short-lived: membership changes converge
	// within the sync interval, and a stale A record pointing at a removed
	// node should not outlive that by much.
	answerTTL = 60
)

// respond decides what to do with one query against the given domain and
// directory snapshot. It returns either a wire-format reply to send, or
// forward=true when the query is outside the VPN domain and belongs to the
// upstream resolver. (nil, false) drops the packet — unparsable input or
// something that is already a response.
func respond(query []byte, domain string, dir directory.Directory) (reply []byte, forward bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil || hdr.Response {
		return nil, false
	}
	// Non-QUERY opcodes (NOTIFY, UPDATE, …) aren't ours to interpret; let the
	// upstream answer or reject them.
	if hdr.OpCode != 0 {
		return nil, true
	}
	questions, err := p.AllQuestions()
	if err != nil || len(questions) != 1 {
		return buildReply(hdr, nil, dnsmessage.RCodeFormatError, nil), false
	}
	q := questions[0]
	if q.Class != dnsmessage.ClassINET {
		return nil, true
	}
	qname := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))

	// Reverse lookups: answer authoritatively for addresses inside the VPN
	// CIDR, forward the rest of the reverse tree.
	if strings.HasSuffix(qname, ".in-addr.arpa") {
		return respondPTR(hdr, q, qname, domain, dir)
	}

	switch {
	case qname == domain:
		// Browsers and stub resolvers probe the apex (A, HTTPS, …); an
		// NXDOMAIN here reads as "the whole zone is dead" to some stacks.
		return buildReply(hdr, &q, dnsmessage.RCodeSuccess, nil), false
	case strings.HasSuffix(qname, "."+domain):
		label := strings.TrimSuffix(qname, "."+domain)
		if strings.Contains(label, ".") {
			return buildReply(hdr, &q, dnsmessage.RCodeNameError, nil), false
		}
		node, ok := nodeByLabel(dir, label)
		if !ok {
			return buildReply(hdr, &q, dnsmessage.RCodeNameError, nil), false
		}
		if q.Type != dnsmessage.TypeA {
			// The name exists but only as an IPv4 mapping. AAAA, HTTPS
			// (type 65 — iOS/Android query it constantly), TXT, … get an
			// empty NOERROR so clients fall through to A instead of
			// treating the name as dead.
			return buildReply(hdr, &q, dnsmessage.RCodeSuccess, nil), false
		}
		addr, err := netip.ParseAddr(node.TunnelIP)
		if err != nil || !addr.Is4() {
			return buildReply(hdr, &q, dnsmessage.RCodeServerFailure, nil), false
		}
		answer := dnsmessage.Resource{
			Header: answerHeader(q.Name, dnsmessage.TypeA),
			Body:   &dnsmessage.AResource{A: addr.As4()},
		}
		return buildReply(hdr, &q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{answer}), false
	default:
		return nil, true
	}
}

func respondPTR(hdr dnsmessage.Header, q dnsmessage.Question, qname, domain string, dir directory.Directory) (reply []byte, forward bool) {
	addr, ok := reverseIPv4(qname)
	if !ok {
		return nil, true
	}
	prefix, err := netip.ParsePrefix(dir.NetworkCIDR)
	if err != nil || !prefix.Masked().Contains(addr) {
		return nil, true
	}
	if q.Type != dnsmessage.TypePTR {
		return buildReply(hdr, &q, dnsmessage.RCodeSuccess, nil), false
	}
	for _, node := range dir.Nodes {
		if node.TunnelIP != addr.String() {
			continue
		}
		target, err := dnsmessage.NewName(strings.ToLower(node.Name) + "." + domain + ".")
		if err != nil {
			return buildReply(hdr, &q, dnsmessage.RCodeServerFailure, nil), false
		}
		answer := dnsmessage.Resource{
			Header: answerHeader(q.Name, dnsmessage.TypePTR),
			Body:   &dnsmessage.PTRResource{PTR: target},
		}
		return buildReply(hdr, &q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{answer}), false
	}
	// Inside the VPN CIDR but unassigned: ours to deny, not the upstream's.
	return buildReply(hdr, &q, dnsmessage.RCodeNameError, nil), false
}

func nodeByLabel(dir directory.Directory, label string) (directory.Node, bool) {
	for _, node := range dir.Nodes {
		if strings.EqualFold(node.Name, label) {
			return node, true
		}
	}
	return directory.Node{}, false
}

func answerHeader(name dnsmessage.Name, t dnsmessage.Type) dnsmessage.ResourceHeader {
	return dnsmessage.ResourceHeader{
		Name:  name,
		Type:  t,
		Class: dnsmessage.ClassINET,
		TTL:   answerTTL,
	}
}

// buildReply assembles a complete response. The question is echoed exactly
// as parsed — original case included, for 0x20-randomizing clients. q may be
// nil (FORMERR for a question section we could not take at face value).
func buildReply(hdr dnsmessage.Header, q *dnsmessage.Question, rcode dnsmessage.RCode, answers []dnsmessage.Resource) []byte {
	replyHdr := dnsmessage.Header{
		ID:               hdr.ID,
		Response:         true,
		Authoritative:    true,
		RecursionDesired: hdr.RecursionDesired,
		// Spoke stubs always set RD; answering RD=1 with RA=0 makes some of
		// them log errors or distrust the server.
		RecursionAvailable: true,
		RCode:              rcode,
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), replyHdr)
	b.EnableCompression()
	if q != nil {
		if err := b.StartQuestions(); err != nil {
			return nil
		}
		if err := b.Question(*q); err != nil {
			return nil
		}
	}
	if len(answers) > 0 {
		if err := b.StartAnswers(); err != nil {
			return nil
		}
		for _, answer := range answers {
			var err error
			switch body := answer.Body.(type) {
			case *dnsmessage.AResource:
				err = b.AResource(answer.Header, *body)
			case *dnsmessage.PTRResource:
				err = b.PTRResource(answer.Header, *body)
			default:
				return nil
			}
			if err != nil {
				return nil
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// servfailFor turns a raw query into a SERVFAIL response in place: same ID,
// question, and opcode, with QR/RA set and the rcode swapped. Used when an
// upstream exchange fails — silence would leave mobile stubs hanging.
func servfailFor(query []byte) []byte {
	if len(query) < headerLen {
		return nil
	}
	out := make([]byte, len(query))
	copy(out, query)
	out[2] |= qrBit                                  // QR: response
	out[2] &^= 0x04                                  // AA off
	out[3] = (out[3] &^ 0x0f) | 0x80 | 0x02          // RA on, RCODE=SERVFAIL
	return out
}

// reverseIPv4 converts "d.c.b.a.in-addr.arpa" to the address a.b.c.d.
func reverseIPv4(qname string) (netip.Addr, bool) {
	rest := strings.TrimSuffix(qname, ".in-addr.arpa")
	parts := strings.Split(rest, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0])
	if err != nil || !addr.Is4() {
		return netip.Addr{}, false
	}
	return addr, true
}
