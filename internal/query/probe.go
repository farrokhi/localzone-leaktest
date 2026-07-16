package query

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/miekg/dns"

	"github.com/farrokhi/localzone-leaktest/internal/dataset"
)

// RandomLabel returns a fresh hex label from crypto/rand, so probe names never
// collide across runs and every query is a genuine cold cache lookup.
func RandomLabel(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ProbeName builds a cold cache probe FQDN under the given zone, for example
// "probe-1a2b3c4d.10.in-addr.arpa.".
func ProbeName(zone string) (string, error) {
	label, err := RandomLabel(4)
	if err != nil {
		return "", err
	}
	return dns.Fqdn(fmt.Sprintf("probe-%s.%s", label, zone)), nil
}

// BaselineName builds a probe FQDN under a real public TLD, used to time a
// query that must actually recurse.
func BaselineName() (string, error) {
	label, err := RandomLabel(4)
	if err != nil {
		return "", err
	}
	return dns.Fqdn(fmt.Sprintf("probe-%s.com", label)), nil
}

// DNSType maps a dataset QType string to a concrete DNS record type.
func DNSType(qtype string) uint16 {
	switch qtype {
	case dataset.QTypePTR:
		return dns.TypePTR
	default:
		return dns.TypeA
	}
}
