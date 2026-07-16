// Package dataset holds the list of locally served DNS zones and special use
// names that the tool probes, expressed as structured data so categories can be
// filtered and the ranges expanded programmatically rather than hardcoded.
//
// Each entry carries its RFC reference. The package deliberately has no DNS
// library dependency so the data and its range expansion can be tested in
// isolation.
package dataset

import "fmt"

// Category keys used for the --category filter.
const (
	CategoryRFC1918     = "rfc1918"    // IPv4 reverse zones for RFC 1918 and link local space (AS112 delegated)
	CategoryIPv4Special = "ip4special" // other special purpose IPv4 reverse zones (served empty by parent/RIR)
	CategoryIPv6        = "ip6"        // IPv6 reverse zones
	CategorySpecial     = "special"    // special use forward names
)

// QType values. Stored as strings so this package stays free of a DNS library
// dependency; the query layer maps them to concrete record types.
const (
	QTypePTR = "PTR"
	QTypeA   = "A"
)

// Zone is one name the tool probes.
type Zone struct {
	// Name is the zone apex or forward name without a trailing dot,
	// for example "10.in-addr.arpa" or "corp".
	Name string
	// Category is one of the Category* keys.
	Category string
	// RFC is a short human reference such as "RFC 1918 (BCP 5)".
	RFC string
	// AS112 is true when the zone is delegated to the AS112 blackhole servers
	// rather than answered empty by the parent or a RIR, which changes what a
	// leaked answer looks like on the wire (RFC 7534, RFC 7535).
	AS112 bool
	// QType is the query type to use, QTypePTR for reverse zones and QTypeA for
	// forward names.
	QType string
	// Informational marks names whose leak-looking answer is by design, like
	// resolver.arpa answered with SVCB by DDR resolvers (RFC 9462).
	Informational bool
}

// Categories returns the category keys in display order.
func Categories() []string {
	return []string{CategoryRFC1918, CategoryIPv4Special, CategoryIPv6, CategorySpecial}
}

// ValidCategory reports whether key names a known category (or "all").
func ValidCategory(key string) bool {
	if key == "all" {
		return true
	}
	for _, c := range Categories() {
		if c == key {
			return true
		}
	}
	return false
}

// Build returns the full dataset with all ranges expanded, in a stable order.
func Build() []Zone {
	var zones []Zone

	// IPv4 reverse, RFC 1918 and link local. These are AS112 delegated.
	zones = append(zones, Zone{Name: "10.in-addr.arpa", Category: CategoryRFC1918, RFC: "RFC 1918 (BCP 5)", AS112: true, QType: QTypePTR})
	for i := 16; i <= 31; i++ { // 172.16.0.0/12 -> 16.172 .. 31.172
		zones = append(zones, Zone{Name: fmt.Sprintf("%d.172.in-addr.arpa", i), Category: CategoryRFC1918, RFC: "RFC 1918 (BCP 5)", AS112: true, QType: QTypePTR})
	}
	zones = append(zones, Zone{Name: "168.192.in-addr.arpa", Category: CategoryRFC1918, RFC: "RFC 1918 (BCP 5)", AS112: true, QType: QTypePTR})
	zones = append(zones, Zone{Name: "254.169.in-addr.arpa", Category: CategoryRFC1918, RFC: "RFC 3927", AS112: true, QType: QTypePTR})

	// IPv4 reverse, other special purpose. Served empty by parent or RIR, not AS112.
	zones = append(zones,
		Zone{Name: "0.in-addr.arpa", Category: CategoryIPv4Special, RFC: "RFC 6303 (BCP 163)", QType: QTypePTR},
		Zone{Name: "127.in-addr.arpa", Category: CategoryIPv4Special, RFC: "RFC 6303 (BCP 163)", QType: QTypePTR},
		Zone{Name: "255.255.255.255.in-addr.arpa", Category: CategoryIPv4Special, RFC: "RFC 6303 (BCP 163)", QType: QTypePTR},
		Zone{Name: "2.0.192.in-addr.arpa", Category: CategoryIPv4Special, RFC: "RFC 5737", QType: QTypePTR},    // TEST-NET-1 192.0.2.0/24
		Zone{Name: "100.51.198.in-addr.arpa", Category: CategoryIPv4Special, RFC: "RFC 5737", QType: QTypePTR}, // TEST-NET-2 198.51.100.0/24
		Zone{Name: "113.0.203.in-addr.arpa", Category: CategoryIPv4Special, RFC: "RFC 5737", QType: QTypePTR},  // TEST-NET-3 203.0.113.0/24
	)
	for i := 64; i <= 127; i++ { // 100.64.0.0/10 CGNAT -> 64.100 .. 127.100
		zones = append(zones, Zone{Name: fmt.Sprintf("%d.100.in-addr.arpa", i), Category: CategoryIPv4Special, RFC: "RFC 6598 (BCP 153), RFC 7793", QType: QTypePTR})
	}

	// IPv6 reverse zones. None are AS112 delegated.
	zones = append(zones,
		Zone{Name: ip6Nibbles("") + "ip6.arpa", Category: CategoryIPv6, RFC: "RFC 4291", QType: QTypePTR},  // unspecified ::
		Zone{Name: ip6Nibbles("1") + "ip6.arpa", Category: CategoryIPv6, RFC: "RFC 4291", QType: QTypePTR}, // loopback ::1
		Zone{Name: "d.f.ip6.arpa", Category: CategoryIPv6, RFC: "RFC 4193", QType: QTypePTR},               // ULA fc00::/7
	)
	for _, n := range []string{"8", "9", "a", "b"} { // link local fe80::/10
		zones = append(zones, Zone{Name: n + ".e.f.ip6.arpa", Category: CategoryIPv6, RFC: "RFC 4291", QType: QTypePTR})
	}
	zones = append(zones,
		Zone{Name: "8.b.d.0.1.0.0.2.ip6.arpa", Category: CategoryIPv6, RFC: "RFC 3849", QType: QTypePTR}, // 2001:db8::/32 documentation
		Zone{Name: "0.f.f.f.3.ip6.arpa", Category: CategoryIPv6, RFC: "RFC 9637", QType: QTypePTR},       // 3fff::/20 documentation
	)

	// Special use forward names.
	zones = append(zones,
		Zone{Name: "home.arpa", Category: CategorySpecial, RFC: "RFC 8375", QType: QTypeA},
		Zone{Name: "service.arpa", Category: CategorySpecial, RFC: "RFC 9665", QType: QTypeA},
		Zone{Name: "resolver.arpa", Category: CategorySpecial, RFC: "RFC 9462", QType: QTypeA, Informational: true},
		Zone{Name: "local", Category: CategorySpecial, RFC: "RFC 6762", QType: QTypeA},
		Zone{Name: "intranet", Category: CategorySpecial, RFC: "RFC 6762 App. G", QType: QTypeA},
		Zone{Name: "internal", Category: CategorySpecial, RFC: "RFC 6762 App. G", QType: QTypeA},
		Zone{Name: "private", Category: CategorySpecial, RFC: "RFC 6762 App. G", QType: QTypeA},
		Zone{Name: "corp", Category: CategorySpecial, RFC: "RFC 6762 App. G", QType: QTypeA},
		Zone{Name: "home", Category: CategorySpecial, RFC: "RFC 6762 App. G", QType: QTypeA},
		Zone{Name: "lan", Category: CategorySpecial, RFC: "RFC 6762 App. G", QType: QTypeA},
		Zone{Name: "onion", Category: CategorySpecial, RFC: "RFC 7686", QType: QTypeA},
	)

	return zones
}

// Filter returns the zones whose category is in the given comma separated key
// list. "all" (or an empty selection containing "all") returns everything.
func Filter(zones []Zone, keys []string) []Zone {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		if k == "all" {
			return zones
		}
		want[k] = true
	}
	var out []Zone
	for _, z := range zones {
		if want[z.Category] {
			out = append(out, z)
		}
	}
	return out
}

// ip6Nibbles builds a reverse nibble prefix from the low order nibbles (least
// significant first), zero padded to 32 so the caller can append "ip6.arpa".
func ip6Nibbles(low string) string {
	out := make([]byte, 0, 64)
	for i := 0; i < len(low); i++ {
		out = append(out, low[i], '.')
	}
	for n := len(low); n < 32; n++ {
		out = append(out, '0', '.')
	}
	return string(out)
}
