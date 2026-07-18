# localzone-leaktest

## TL;DR

Your resolver is supposed to answer queries for private names (`10.in-addr.arpa`, `home.arpa`, `corp`, ...) itself. This tool sends it a batch of such queries and reports which ones leak to the public internet.

```
go install github.com/farrokhi/localzone-leaktest@latest
localzone-leaktest              # test the system resolver
localzone-leaktest @192.168.1.1 # or your router, or any resolver
```

Every row `[LOCAL]` and exit code 0 means your resolver behaves; `[LEAK]` rows name where the query ended up.

`localzone-leaktest` checks whether a DNS resolver answers the IANA locally served zones and special use names itself (RFC 6303 and related), or leaks those queries to the public internet. Leaking discloses internal names and network structure to third parties, loads the AS112 project and the root servers, and is slower than a local answer, which a well behaved resolver returns from a built in empty zone in about a millisecond (or whatever your distance is to the resolver, which is expected to be much shorter than to a root server, unless you live in a datacenter). Point it at your system resolver, your router, a public resolver like `9.9.9.9`, or any server you name.

This is not a VPN DNS leak test. There are many of those on the internet. This tool does not look at VPN tunnels. **It checks whether a resolver keeps standardized private and special use names local instead of forwarding them to the root and the regional registries.**

## Install

```
go install github.com/farrokhi/localzone-leaktest@latest
```

Prebuilt binaries for Linux (amd64, arm64), macOS (arm64), Windows (amd64), and FreeBSD (amd64) are on the [releases page](https://github.com/farrokhi/localzone-leaktest/releases). Or build from a checkout with `go build -o localzone-leaktest .`; requires Go 1.25 or newer. The binary has no runtime dependencies.

## Usage

```
localzone-leaktest                     # test the system resolver
localzone-leaktest @9.9.9.9            # test a specific resolver
localzone-leaktest -s 192.168.1.1      # test your home router
localzone-leaktest -c rfc1918 -v       # only the RFC 1918 reverse zones, verbose
localzone-leaktest --json | jq .       # machine readable output
```

```
-s, --server HOST     resolver to test; also accepts a leading @HOST argument
-p, --port PORT       resolver port (default 53)
-c, --category LIST   filter: rfc1918, ip4special, ip6, special, all (default all)
-4 / -6               force IPv4 or IPv6 transport to the resolver
-j, --json            emit machine readable JSON instead of the table
-l, --list            print the test names and exit without querying
-t, --timeout SECONDS per query timeout (default 2)
    --tries N         per query attempt count (default 1)
-v, --verbose         show the raw signal detail per name
-q, --quiet           print only the summary
    --no-color        disable ANSI color (auto disabled when output is not a terminal)
    --strict          treat INCONCLUSIVE results as a non-zero exit for CI
    --concurrency N   number of parallel probes (default 10)
-V, --version         print the version and exit
```

A clean run against a resolver that serves these zones locally:

```
Resolver: 9.9.9.9:53    Recursion baseline: 24 ms

NAME                  CATEGORY  STATUS         TIME  SOURCE
168.192.in-addr.arpa  rfc1918   [LOCAL]         1ms  local policy answer (no SOA), confirmed by non-recursive query
corp                  special   [LOCAL]         1ms  root-derived answer (root SOA, synthesized or queried)
home                  special   [LOCAL]         1ms  local policy answer (no SOA)

Summary: 109 local, 0 leaked, 0 hijacked, 0 inconclusive, 0 errors (of 109 tested)
109 of 109 names handled locally, no leaks.
```

A resolver that forwards these queries to the public DNS shows leaks instead:

```
10.in-addr.arpa       rfc1918     [LEAK]         19ms  leaked to AS112 (prisoner.iana.org)
2.0.192.in-addr.arpa  ip4special  [LEAK]         21ms  leaked to parent operator (z.arin.net)
64.100.in-addr.arpa   ip4special  [LEAK]         20ms  leaked to IANA empty zone (sns.dns.icann.org)
```

## Interpreting the results

Two things surprise people. A bare NXDOMAIN with no SOA is a normal local answer. And a root SOA (`a.root-servers.net`) on names like `home` or `corp` also counts as local: the resolver either synthesized it from cached root NSEC records (aggressive NSEC, RFC 8198) or asked the root, and with QNAME minimization (RFC 9156) at most the bare TLD label leaves the resolver either way. Unlike the reverse zones, no registry mandates local service for these TLDs, so a root-derived negative is the expected behavior. Only a query that reaches the AS112 sink or the real authoritative servers, or one with fabricated answer data, is a problem.

The verdict comes from the SOA record in the negative answer. RFC 2308 requires authoritative servers (section 3) and caches (section 5) to attach the zone SOA to negative answers, so a recursed answer always names its source, and an answer with no SOA at all was synthesized by resolver policy. The TIME column and the recursion baseline in the header are shown for context only; they never decide a verdict. When an answer has no SOA, the tool sends one follow-up query with recursion disabled (RD=0) under a fresh random name: a resolver that serves the zone itself still answers, one that would have to recurse typically refuses, and an answer carrying a public SOA exposes leaked data sitting in the cache. Each name gets one verdict:

- `LOCAL`: the query never reached the servers these zones are meant to be kept from. Shown by a policy answer with no SOA, a root-derived answer (root SOA), or the resolver's own synthetic SOA. This is what you want.
- `LEAK`: the answer originates from the public DNS, shown by the AS112 fingerprint (a per-zone SOA under `prisoner.iana.org`, `blackhole`, or `as112`), a parent operator or RIR SOA such as `z.arin.net`, ICANN's empty zone primary `sns.dns.icann.org`, or leaked data found in the cache by the non-recursive check. A fast answer does not clear a leak; it just means the leaked data was served from cache this time.
- `HIJACK`: an address record came back for a name that cannot exist, usually NXDOMAIN rewriting, a captive portal, or ISP redirection.
- `INCONCLUSIVE`: reserved for response shapes the tool cannot read. It should be rare, and it is not counted as a failure unless you pass `--strict`.
- `ERROR`: SERVFAIL, REFUSED, timeout, or another anomaly.

If you find a leak, you can enable RFC 6303 local zones on your resolver, switch to a resolver that serves them, or accept it on a private network that uses one of these names.

## Background

Recursive resolvers should serve the private reverse zones (such as the reverse DNS for `10.0.0.0/8`) and special use names (such as `home.arpa` or `corp`) from built in empty zones per RFC 6303, and the AS112 project absorbs the queries that escape. Only some zones are delegated to AS112: the RFC 1918 and link local IPv4 reverse zones go to the AS112 nameservers `blackhole-1.iana.org` and `blackhole-2.iana.org`, ICANN serves others empty itself on the `iana-servers.net` set (the CGNAT reverse zones, with `sns.dns.icann.org` as the SOA primary), while the remaining reverse zones are answered by the parent operators or the RIRs, and the forward names resolve against the root.

A few caveats: `local` is the mDNS namespace and is supposed to resolve over multicast. `resolver.arpa` is treated as informational, since DDR aware resolvers answer it with SVCB, and is always local to the resolver. And split horizon networks may serve some of these names, so a leak verdict there can be expected.

## Is it bad if private queries leave my network?

The best person to answer that question is yourself. It depends on your risk profile and privacy consciousness. Is it bad if a stranger overhears your private conversation with a friend? Is it bad if a passerby looks at your phone screen while you are texting?

Generally these private queries are meant to stay within your network boundary. Or if they leave, they should not go very far. Your resolver, assuming that it is very close to your network, should not really allow these queries to go further into the tubes. The earlier you drop these on the floor, the less chance strangers have to look at (or respond to) your private queries.

## The dataset

The tool tests 109 names. The reverse zone ranges are expanded programmatically (for example `16.172.in-addr.arpa` through `31.172.in-addr.arpa`). Run `localzone-leaktest --list` for the full set.

| Category | Covers | RFC / BCP | AS112 |
|----------|--------|-----------|-------|
| `rfc1918` | `10`, `172.16/12`, `192.168/16` reverse, and `169.254/16` link local reverse | RFC 1918, RFC 3927 | yes |
| `ip4special` | `0`, `127`, broadcast, TEST-NET-1/2/3, and CGNAT `100.64/10` reverse | RFC 6303, RFC 5737, RFC 6598, RFC 7793 | no |
| `ip6` | unspecified, loopback, ULA, link local, and documentation reverse | RFC 4291, RFC 4193, RFC 3849, RFC 9637 | no |
| `special` | `home.arpa`, `service.arpa`, `resolver.arpa`, `local`, the private use TLDs, and `onion` | RFC 8375, RFC 9665, RFC 9462, RFC 6762, RFC 7686 | no |

## Compatibility and exit codes

Tested on Linux, macOS, and FreeBSD. With no resolver specified, it reads `/etc/resolv.conf`. But you may want to compare different resolvers, so you should specify your target resolver using `-s`.

There are multiple exit codes: `0` when every name was handled locally, `1` when any leak or hijack was found, and `2` for a usage or environment error such as an unreachable resolver. A resolver that does not respond at all (for example one blocked by a firewall or VPN) fails fast after roughly two query timeouts instead of probing every name.

## References

- RFC 6303 Locally Served DNS Zones (BCP 163): https://www.rfc-editor.org/rfc/rfc6303
- RFC 1918 Address Allocation for Private Internets (BCP 5): https://www.rfc-editor.org/rfc/rfc1918
- RFC 3927 Dynamic Configuration of IPv4 Link-Local Addresses: https://www.rfc-editor.org/rfc/rfc3927
- RFC 5737 IPv4 Address Blocks Reserved for Documentation: https://www.rfc-editor.org/rfc/rfc5737
- RFC 6598 IANA-Reserved IPv4 Prefix for Shared Address Space (BCP 153): https://www.rfc-editor.org/rfc/rfc6598
- RFC 7793 Adding 100.64.0.0/10 to the IPv4 Locally-Served DNS Zones Registry: https://www.rfc-editor.org/rfc/rfc7793
- RFC 4291 IP Version 6 Addressing Architecture: https://www.rfc-editor.org/rfc/rfc4291
- RFC 4193 Unique Local IPv6 Unicast Addresses: https://www.rfc-editor.org/rfc/rfc4193
- RFC 3849 IPv6 Address Prefix Reserved for Documentation: https://www.rfc-editor.org/rfc/rfc3849
- RFC 9637 Expanding the IPv6 Documentation Space: https://www.rfc-editor.org/rfc/rfc9637
- RFC 8375 Special-Use Domain 'home.arpa.': https://www.rfc-editor.org/rfc/rfc8375
- RFC 9665 Service Registration Protocol for DNS-Based Service Discovery: https://www.rfc-editor.org/rfc/rfc9665
- RFC 9462 Discovery of Designated Resolvers: https://www.rfc-editor.org/rfc/rfc9462
- RFC 6762 Multicast DNS: https://www.rfc-editor.org/rfc/rfc6762
- RFC 7686 The ".onion" Special-Use Domain Name: https://www.rfc-editor.org/rfc/rfc7686
- RFC 7534 AS112 Nameserver Operations: https://www.rfc-editor.org/rfc/rfc7534
- RFC 7535 AS112 Redirection Using DNAME: https://www.rfc-editor.org/rfc/rfc7535
- RFC 8914 Extended DNS Errors: https://www.rfc-editor.org/rfc/rfc8914
- RFC 2308 Negative Caching of DNS Queries (DNS NCACHE): https://www.rfc-editor.org/rfc/rfc2308
- RFC 9156 DNS Query Name Minimisation to Improve Privacy: https://www.rfc-editor.org/rfc/rfc9156

## License

MIT. See LICENSE.
