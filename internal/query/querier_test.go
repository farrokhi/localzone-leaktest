package query

import (
	"strings"
	"testing"
)

func TestResolveServerExplicit(t *testing.T) {
	cases := []struct {
		name   string
		server string
		port   int
		want   string
	}{
		{"host default port", "1.1.1.1", 0, "1.1.1.1:53"},
		{"host with -p", "1.1.1.1", 5353, "1.1.1.1:5353"},
		{"host:port in string wins", "1.1.1.1:8053", 5353, "1.1.1.1:8053"},
		{"bracketed ipv6 host:port", "[2001:db8::1]:5353", 0, "[2001:db8::1]:5353"},
		{"bare ipv6 literal", "2001:db8::1", 5353, "[2001:db8::1]:5353"},
		{"bare ipv6 default port", "::1", 0, "[::1]:53"},
	}
	for _, c := range cases {
		got, err := resolveServer(c.server, c.port)
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: resolveServer(%q, %d) = %q, want %q", c.name, c.server, c.port, got, c.want)
		}
	}
}

// TestResolveServerSystemPortOverride checks that an explicit -p overrides the
// resolv.conf port on the system resolver path. It is skipped where the system
// resolver cannot be read.
func TestResolveServerSystemPortOverride(t *testing.T) {
	got, err := resolveServer("", 5353)
	if err != nil {
		t.Skipf("no usable system resolver: %v", err)
	}
	if !strings.HasSuffix(got, ":5353") {
		t.Errorf("system resolver with -p 5353 = %q, want a :5353 suffix", got)
	}
}
