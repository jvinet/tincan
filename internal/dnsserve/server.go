// Package dnsserve is the VPN DNS listener a hub runs for plain-WireGuard
// spokes. Full tincan members resolve names from their managed /etc/hosts
// block and never need this; spokes can't (no daemon, no root), so their
// rendered configs carry "DNS = <hub tunnel IP>, <domain>" and the hub
// answers <name>.<domain> from its cached directory.
//
// The critical constraint: a mobile WireGuard app applies that DNS line as
// the device's only resolver while the tunnel is up — every query for every
// domain lands here, not just VPN names. Refusing the rest would cut the
// device off from the internet, so anything outside the VPN domain is
// proxied verbatim to an upstream resolver.
//
// UDP only. Authoritative answers are single A/PTR records that always fit
// 512 bytes; forwarded traffic is relayed byte-for-byte, so EDNS, HTTPS
// (type 65), and DNSSEC queries pass through untouched. Wire parsing is
// delegated to golang.org/x/net/dns/dnsmessage (the codec the Go resolver
// itself uses); only the serving logic lives here.
package dnsserve

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/jvinet/tincan/internal/directory"
)

// DirectorySource returns the latest synced directory snapshot. Same shape
// as the discovery subsystem's source: the daemon swaps the snapshot every
// sync, and the server picks it up per query — no restart on membership
// changes.
type DirectorySource func() directory.Directory

type Config struct {
	// Addr is the UDP listen address, normally "<self tunnel IP>:53".
	Addr string
	// Domain is the VPN DNS domain, lowercase with no trailing dot. Queries
	// at or under it are answered from the directory; everything else is
	// forwarded.
	Domain string
	// Upstream is where non-VPN queries are proxied, host[:port] (port 53
	// implied). The caller resolves its default (see DefaultUpstream).
	Upstream string
	// Timeout bounds one upstream exchange. Defaults to 5s.
	Timeout time.Duration
}

// maxForwards caps concurrently in-flight upstream exchanges. Each forward
// holds a socket and a goroutine; past the cap, queries are dropped and the
// client retries — the standard DNS failure mode.
const maxForwards = 256

type Server struct {
	cfg      Config
	conn     *net.UDPConn
	upstream *net.UDPAddr
	source   DirectorySource
	sem      chan struct{}
	closed   atomic.Bool
}

// Start binds cfg.Addr and serves until ctx is canceled or Close is called.
// The bind error is returned verbatim so callers can branch on EADDRINUSE
// (the host may already run dnsmasq/Pi-hole).
func Start(ctx context.Context, cfg Config, source DirectorySource) (*Server, error) {
	if cfg.Domain == "" {
		return nil, errors.New("dnsserve: empty domain")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	upstream, err := net.ResolveUDPAddr("udp", withDefaultPort(cfg.Upstream))
	if err != nil {
		return nil, fmt.Errorf("resolve upstream %q: %w", cfg.Upstream, err)
	}
	laddr, err := net.ResolveUDPAddr("udp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen address %q: %w", cfg.Addr, err)
	}
	// An upstream pointing back at the listener would bounce every non-VPN
	// query to itself until the forward cap fills.
	if upstream.String() == laddr.String() {
		return nil, fmt.Errorf("upstream %s is the listener itself; configure [dns] upstream", upstream)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		conn:     conn,
		upstream: upstream,
		source:   source,
		sem:      make(chan struct{}, maxForwards),
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	go s.serve()
	return s, nil
}

func (s *Server) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return s.conn.Close()
}

// LocalAddr reports the bound address (tests listen on port 0).
func (s *Server) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *Server) serve() {
	buf := make([]byte, 1500)
	for {
		n, client, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() {
				return
			}
			slog.Debug("dns read failed", "error", err)
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		reply, forward := respond(query, s.cfg.Domain, s.source())
		switch {
		case forward:
			select {
			case s.sem <- struct{}{}:
			default:
				slog.Debug("dns forward dropped (at concurrency cap)", "client", client)
				continue
			}
			go s.forward(query, client)
		case reply != nil:
			if _, err := s.conn.WriteToUDP(reply, client); err != nil {
				slog.Debug("dns reply write failed", "client", client, "error", err)
			}
		}
	}
}

// forward proxies query to the upstream resolver and relays the raw reply.
// A fresh socket per exchange gives every query its own ephemeral source
// port, so upstream replies can't be confused across queries (the query ID
// is double-checked anyway). On failure the client gets SERVFAIL — mobile
// stub resolvers fail over quickly on SERVFAIL but stall on silence.
func (s *Server) forward(query []byte, client *net.UDPAddr) {
	defer func() { <-s.sem }()
	reply := s.exchange(query)
	if reply == nil {
		reply = servfailFor(query)
		if reply == nil {
			return
		}
	}
	if _, err := s.conn.WriteToUDP(reply, client); err != nil {
		slog.Debug("dns forward reply write failed", "client", client, "error", err)
	}
}

func (s *Server) exchange(query []byte) []byte {
	conn, err := net.DialUDP("udp", nil, s.upstream)
	if err != nil {
		slog.Debug("dns upstream dial failed", "upstream", s.upstream, "error", err)
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	if _, err := conn.Write(query); err != nil {
		slog.Debug("dns upstream write failed", "upstream", s.upstream, "error", err)
		return nil
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			slog.Debug("dns upstream read failed", "upstream", s.upstream, "error", err)
			return nil
		}
		// Accept only a response carrying our query's ID; anything else on
		// this socket is noise or spoofing and is skipped until the deadline.
		if n < headerLen || buf[0] != query[0] || buf[1] != query[1] || buf[2]&qrBit == 0 {
			continue
		}
		return buf[:n]
	}
}

// withDefaultPort appends ":53" to a bare host, the same convention the
// [dns] upstream config field and the dns drop's resolver use.
func withDefaultPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, "53")
	}
	return addr
}
