package dnsserve

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

const resolvConfPath = "/etc/resolv.conf"

// DefaultUpstream returns the system's first resolv.conf nameserver as a
// host:port, the natural place to send spokes' non-VPN queries. A loopback
// nameserver (systemd-resolved's 127.0.0.53) is correct here: the proxy runs
// on this host, so its local resolver answers.
func DefaultUpstream() (string, error) {
	return upstreamFromResolvConf(resolvConfPath)
}

func upstreamFromResolvConf(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		host := fields[1]
		if net.ParseIP(host) == nil {
			continue
		}
		return net.JoinHostPort(host, "53"), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no nameserver entries in %s", path)
}
