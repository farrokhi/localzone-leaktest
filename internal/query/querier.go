// Package query sends DNS probes and reduces each response to a ProbeResult
// carrying the signals the classifier needs: the RCODE, any answer records, the
// authority SOA source, an Extended DNS Error if present, and the round trip
// time. It hides the DNS library behind a small surface so an alternate
// transport (DoT, DoH) could be added without touching the rest of the tool.
package query

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ProbeResult is the parsed outcome of a single query. It is intentionally free
// of DNS library types so the classifier can be exercised with plain values.
type ProbeResult struct {
	QName     string
	QType     uint16
	RCode     int
	RCodeText string

	// Answers holds a short textual form of each answer record, for display and
	// hijack detection, for example "A 10.1.2.3" or "PTR host.example.".
	Answers   []string
	HasAnswer bool

	// AA is the Authoritative Answer bit, shown in verbose and JSON output. An
	// AS112 node and a local RFC 6303 empty zone both set it, so it cannot
	// distinguish the two and takes no part in classification.
	AA bool

	// SOA source from the authority section of a negative answer.
	HasSOA   bool
	SOAOwner string // owner name of the SOA record
	SOAMName string // primary master (MNAME)
	SOARName string // responsible mailbox (RNAME)

	// EDECode is the RFC 8914 Extended DNS Error info code, or -1 when absent.
	EDECode int
	EDEText string

	RTT       time.Duration
	Truncated bool
	Err       error // transport error or timeout; non nil means the probe failed
}

// Config describes how to reach the resolver under test.
type Config struct {
	// Server is the resolver host, optionally with a ":port". Empty means use
	// the system default resolver.
	Server string
	// Port is used when Server carries no port of its own. Zero means 53.
	Port int
	// Net is the transport network passed to the DNS client: "udp", "udp4", or
	// "udp6". Empty defaults to "udp".
	Net string
	// Timeout bounds each individual query. Zero means two seconds.
	Timeout time.Duration
	// Tries is the number of attempts per query. Zero means one.
	Tries int
}

// Querier sends probes to a fixed resolver.
type Querier struct {
	server string // resolved host:port
	net    string // "udp", "udp4", "udp6"
	client *dns.Client
	tries  int
}

// New builds a Querier, resolving the system default resolver when Config.Server
// is empty.
func New(cfg Config) (*Querier, error) {
	netProto := cfg.Net
	if netProto == "" {
		netProto = "udp"
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	tries := cfg.Tries
	if tries < 1 {
		tries = 1
	}

	addr, err := resolveServer(cfg.Server, cfg.Port)
	if err != nil {
		return nil, err
	}

	return &Querier{
		server: addr,
		net:    netProto,
		client: &dns.Client{Net: netProto, Timeout: timeout},
		tries:  tries,
	}, nil
}

// Server returns the resolved host:port of the resolver under test.
func (q *Querier) Server() string { return q.server }

// Query sends one recursive probe and returns the parsed result. A transport
// error or timeout is captured in ProbeResult.Err rather than returned, so
// callers can classify it as an ERROR outcome uniformly.
func (q *Querier) Query(qname string, qtype uint16) ProbeResult {
	return q.query(qname, qtype, true)
}

// QueryNonRecursive sends one probe with the RD bit clear. A resolver holding
// the zone as local data answers it; a purely recursing resolver can only
// answer from cache and typically refuses.
func (q *Querier) QueryNonRecursive(qname string, qtype uint16) ProbeResult {
	return q.query(qname, qtype, false)
}

func (q *Querier) query(qname string, qtype uint16, rd bool) ProbeResult {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = rd
	// Advertise EDNS0 so a resolver may attach an Extended DNS Error and so we
	// can receive responses larger than 512 bytes.
	m.SetEdns0(4096, false)

	var (
		resp *dns.Msg
		rtt  time.Duration
		err  error
	)
	for attempt := 0; attempt < q.tries; attempt++ {
		resp, rtt, err = q.client.Exchange(m, q.server)
		if err == nil {
			break
		}
	}
	if err != nil {
		return ProbeResult{QName: dns.Fqdn(qname), QType: qtype, EDECode: -1, RTT: rtt, Err: err}
	}

	// Retry truncated UDP answers over TCP so the authority section survives.
	if resp.Truncated && strings.HasPrefix(q.net, "udp") {
		tcpClient := &dns.Client{Net: tcpNet(q.net), Timeout: q.client.Timeout}
		if tcpResp, tcpRTT, tcpErr := tcpClient.Exchange(m, q.server); tcpErr == nil {
			resp, rtt = tcpResp, tcpRTT
		}
	}

	return ResultFromMsg(resp, dns.Fqdn(qname), qtype, rtt, nil)
}

// ResultFromMsg reduces a dns.Msg to a ProbeResult. It is exported so the
// classifier tests can build results from canned wire format responses without
// any network access.
func ResultFromMsg(m *dns.Msg, qname string, qtype uint16, rtt time.Duration, err error) ProbeResult {
	r := ProbeResult{QName: qname, QType: qtype, EDECode: -1, RTT: rtt, Err: err}
	if m == nil {
		return r
	}
	r.RCode = m.Rcode
	r.RCodeText = dns.RcodeToString[m.Rcode]
	r.Truncated = m.Truncated
	r.AA = m.Authoritative

	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			r.Answers = append(r.Answers, "A "+v.A.String())
		case *dns.AAAA:
			r.Answers = append(r.Answers, "AAAA "+v.AAAA.String())
		case *dns.PTR:
			r.Answers = append(r.Answers, "PTR "+v.Ptr)
		case *dns.CNAME:
			r.Answers = append(r.Answers, "CNAME "+v.Target)
		case *dns.SVCB:
			r.Answers = append(r.Answers, "SVCB "+v.Target)
		case *dns.HTTPS:
			r.Answers = append(r.Answers, "HTTPS "+v.Target)
		}
	}
	r.HasAnswer = len(r.Answers) > 0

	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			r.HasSOA = true
			r.SOAOwner = soa.Hdr.Name
			r.SOAMName = soa.Ns
			r.SOARName = soa.Mbox
			break
		}
	}

	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if ede, ok := o.(*dns.EDNS0_EDE); ok {
				r.EDECode = int(ede.InfoCode)
				r.EDEText = edeText(ede)
				break
			}
		}
	}

	return r
}

// edeText renders an Extended DNS Error as a "purpose: extra" string.
func edeText(ede *dns.EDNS0_EDE) string {
	name := dns.ExtendedErrorCodeToString[ede.InfoCode]
	if name == "" {
		name = "Unknown"
	}
	if ede.ExtraText != "" {
		return name + ": " + ede.ExtraText
	}
	return name
}

// resolveServer returns a host:port address for the resolver, falling back to
// the system default resolver when server is empty. A zero port means the
// caller did not pass -p, so the default (or the resolv.conf port) applies.
func resolveServer(server string, port int) (string, error) {
	if server == "" {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return "", fmt.Errorf("reading system resolver from /etc/resolv.conf: %w", err)
		}
		if len(cfg.Servers) == 0 {
			return "", fmt.Errorf("no system resolver configured in /etc/resolv.conf")
		}
		// An explicit -p overrides the resolv.conf port.
		p := cfg.Port
		if port != 0 {
			p = strconv.Itoa(port)
		} else if p == "" {
			p = "53"
		}
		return net.JoinHostPort(cfg.Servers[0], p), nil
	}
	// If the caller already supplied a port in the server string, honor it.
	if host, p, err := net.SplitHostPort(server); err == nil {
		return net.JoinHostPort(host, p), nil
	}
	if port == 0 {
		port = 53
	}
	return net.JoinHostPort(server, strconv.Itoa(port)), nil
}

// tcpNet maps a udp network to its tcp counterpart, preserving address family.
func tcpNet(udp string) string {
	switch udp {
	case "udp4":
		return "tcp4"
	case "udp6":
		return "tcp6"
	default:
		return "tcp"
	}
}
