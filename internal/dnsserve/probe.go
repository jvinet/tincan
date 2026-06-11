package dnsserve

import (
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Probe reports whether a DNS server at addr answers an A query for the
// domain apex within timeout. `status` runs in a different process from the
// daemon, so an actual query is the only honest liveness check.
func Probe(addr, domain string, timeout time.Duration) bool {
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		return false
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 64), dnsmessage.Header{ID: 0x7c54, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return false
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		return false
	}
	query, err := b.Finish()
	if err != nil {
		return false
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < headerLen {
		return false
	}
	return buf[0] == query[0] && buf[1] == query[1] && buf[2]&qrBit != 0
}
