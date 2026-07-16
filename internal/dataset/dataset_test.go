package dataset

import (
	"strings"
	"testing"
)

func TestBuildCounts(t *testing.T) {
	zones := Build()

	counts := map[string]int{}
	for _, z := range zones {
		counts[z.Category]++
	}

	// 10 + (172.16..31 = 16) + 168.192 + 254.169
	if got := counts[CategoryRFC1918]; got != 19 {
		t.Errorf("rfc1918 count = %d, want 19", got)
	}
	// 0, 127, 255.255.255.255, 3 TEST-NETs + CGNAT (100.64/10 = 64 zones)
	if got := counts[CategoryIPv4Special]; got != 70 {
		t.Errorf("ip4special count = %d, want 70", got)
	}
	// unspecified, loopback, ULA, 4 link local, 2001:db8, 3fff
	if got := counts[CategoryIPv6]; got != 9 {
		t.Errorf("ip6 count = %d, want 9", got)
	}
	if got := counts[CategorySpecial]; got != 11 {
		t.Errorf("special count = %d, want 11", got)
	}
	if len(zones) != 109 {
		t.Errorf("total count = %d, want 109", len(zones))
	}
}

func TestBuildKnownNames(t *testing.T) {
	zones := Build()
	names := map[string]Zone{}
	for _, z := range zones {
		names[z.Name] = z
	}

	cases := []struct {
		name  string
		cat   string
		as112 bool
		qtype string
	}{
		{"10.in-addr.arpa", CategoryRFC1918, true, QTypePTR},
		{"16.172.in-addr.arpa", CategoryRFC1918, true, QTypePTR},
		{"31.172.in-addr.arpa", CategoryRFC1918, true, QTypePTR},
		{"254.169.in-addr.arpa", CategoryRFC1918, true, QTypePTR},
		{"0.in-addr.arpa", CategoryIPv4Special, false, QTypePTR},
		{"64.100.in-addr.arpa", CategoryIPv4Special, false, QTypePTR},
		{"127.100.in-addr.arpa", CategoryIPv4Special, false, QTypePTR},
		{"d.f.ip6.arpa", CategoryIPv6, false, QTypePTR},
		{"corp", CategorySpecial, false, QTypeA},
		{"onion", CategorySpecial, false, QTypeA},
	}
	for _, c := range cases {
		z, ok := names[c.name]
		if !ok {
			t.Errorf("missing zone %q", c.name)
			continue
		}
		if z.Category != c.cat || z.AS112 != c.as112 || z.QType != c.qtype {
			t.Errorf("zone %q = {cat:%s as112:%v qtype:%s}, want {cat:%s as112:%v qtype:%s}",
				c.name, z.Category, z.AS112, z.QType, c.cat, c.as112, c.qtype)
		}
	}

	// The 172.16/12 range must not overshoot its bounds.
	if _, ok := names["15.172.in-addr.arpa"]; ok {
		t.Error("15.172.in-addr.arpa should not be present")
	}
	if _, ok := names["32.172.in-addr.arpa"]; ok {
		t.Error("32.172.in-addr.arpa should not be present")
	}
}

func TestIP6Nibbles(t *testing.T) {
	unspecified := ip6Nibbles("") + "ip6.arpa"
	if strings.Count(unspecified, "0.") != 32 {
		t.Errorf("unspecified nibble count = %d, want 32", strings.Count(unspecified, "0."))
	}
	loopback := ip6Nibbles("1") + "ip6.arpa"
	want := "1." + strings.Repeat("0.", 31) + "ip6.arpa"
	if loopback != want {
		t.Errorf("loopback = %q, want %q", loopback, want)
	}
}

func TestResolverArpaInformational(t *testing.T) {
	for _, z := range Build() {
		if z.Name == "resolver.arpa" && !z.Informational {
			t.Error("resolver.arpa must be marked informational")
		}
	}
}

func TestFilter(t *testing.T) {
	zones := Build()
	if got := len(Filter(zones, []string{"all"})); got != len(zones) {
		t.Errorf("filter all = %d, want %d", got, len(zones))
	}
	only := Filter(zones, []string{CategorySpecial})
	for _, z := range only {
		if z.Category != CategorySpecial {
			t.Errorf("filter leaked category %s", z.Category)
		}
	}
	if len(only) != 11 {
		t.Errorf("filter special = %d, want 11", len(only))
	}
}
