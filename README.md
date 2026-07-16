# localzone-leaktest

`localzone-leaktest` checks whether a DNS resolver answers the IANA locally served zones and special use names itself (RFC 6303 and related), or leaks those queries to the public internet. Leaking discloses internal names and network structure to third parties, loads the AS112 project and the root servers, and is slower than a local answer, which a well behaved resolver returns from a built in empty zone in about a millisecond (or whatever your distance is to the resolver, which is expected to be much shorter than a root server, unless you live in a datacenter). Point it at your system resolver, your router, a public resolver like `9.9.9.9`, or any server you name.

Please note that this is not a VPN DNS leak test. There are many of them on the internet. This tool does not look at VPN tunnels. **It checks whether a resolver keeps standardized private and special use names local instead of forwarding them to the root and the regional registries.**

## Install

```
go install github.com/farrokhi/localzone-leaktest@latest
```

Or build from a checkout with `go build -o localzone-leaktest .`. Requires Go 1.25 or newer. The binary has no runtime dependencies and runs on Linux, macOS, and FreeBSD.

## Usage

```
localzone-leaktest                     # test the system resolver
localzone-leaktest @1.1.1.1            # test a specific resolver
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
168.192.in-addr.arpa  rfc1918   [LOCAL]         1ms  served locally (no SOA, low query time)
corp                  special   [LOCAL]         1ms  served locally (root SOA)
home                  special   [LOCAL]         1ms  served locally (no SOA, low query time)

Summary: 109 local, 0 leaked, 0 hijacked, 0 inconclusive, 0 errors (of 109 tested)
109 of 109 names handled locally, no leaks.
```

A resolver that forwards these queries to the public DNS shows leaks instead:

```
10.in-addr.arpa       rfc1918   [LEAK]         19ms  leaked to AS112 (prisoner.iana.org)
corp                  special   [LEAK]         22ms  no SOA, query time at recursion baseline
```

## Interpreting the results

Two things surprise people. A bare NXDOMAIN with no SOA is a normal local answer, and a root SOA (`a.root-servers.net`) is also local, because resolvers synthesize it from the signed root (aggressive NSEC, RFC 8198). Only a query that reaches the AS112 sink or the real authoritative servers, or one with fabricated answer data, is a problem.

The tool uses query time as its primary signal, comparing each name against the recursion baseline shown in the header, and reads the SOA to confirm. It is not very accurate, but mostly gets the job done. Each name gets one verdict:

- `LOCAL`: the resolver kept the query local (answer far below the baseline, or a local, root, or absent SOA). This is what you want.
- `LEAK`: the query reached the public DNS, shown by the AS112 fingerprint (a per-zone SOA under `prisoner.iana.org`, `blackhole`, or `as112`) or by a query time at the baseline with nothing local to explain it.
- `HIJACK`: an address record came back for a name that cannot exist, usually NXDOMAIN rewriting, a captive portal, or ISP redirection.
- `INCONCLUSIVE`: the signals disagree, for example an ambiguous parent operator SOA at a mid range query time. It is reported, but it is not considered a failure, unless you pass `--strict`.
- `ERROR`: SERVFAIL, REFUSED, timeout, or another anomaly.

If you find a leak, you can enable RFC 6303 local zones on your resolver, switch to a resolver that serves them, or accept it on a private network that uses one of these names. 

## Background

Recursive resolvers should serve the private reverse zones (such as the reverse DNS for `10.0.0.0/8`) and special use names (such as `home.arpa` or `corp`) from built in empty zones per RFC 6303, and the AS112 project absorbs the ones that escape. Only some zones are delegated to AS112: the RFC 1918 and link local IPv4 reverse zones go to the AS112 nameservers `blackhole-1.iana.org` and `blackhole-2.iana.org`, while the other reverse zones are served by the parent operators or the RIRs, and the forward names resolve against the root. That is why a leaked answer looks different from zone to zone.

A few caveats. `local` is the mDNS namespace and normally resolves over multicast. `resolver.arpa` is treated as informational, since DDR aware resolvers answer it with SVCB by design. And split horizon networks may serve some of these names, so a leak verdict there can be expected.

## Is it bad if Private Queries leave my network?

You are the best person to answer that question. It depends on your risk profile. Is it bad if a stranger overhears your private conversation with a friend? Is it bad if a passerby looks as your laptop screen while you are chatting? Is it bad if someone finds a copy of your ID card or passport on the street?

Generally these private queries are meant to stay within your network. Or if they leave, they should not go very far. Your resolver, assuming that it is very close to your network, should not really allow these queries to go further into the tubes. The earlier you drop these on the floor, the less chance strangers have to look at (or respond to) your private queries. 

## The dataset

The tool tests 109 names. The reverse zone ranges are expanded programmatically (for example `16.172.in-addr.arpa` through `31.172.in-addr.arpa`). Run `localzone-leaktest --list` for the full set.

| Category | Covers | RFC / BCP | AS112 |
|----------|--------|-----------|-------|
| `rfc1918` | `10`, `172.16/12`, `192.168/16` reverse, and `169.254/16` link local reverse | RFC 1918, RFC 3927 | yes |
| `ip4special` | `0`, `127`, broadcast, TEST-NET-1/2/3, and CGNAT `100.64/10` reverse | RFC 6303, RFC 5737, RFC 6598, RFC 7793 | no |
| `ip6` | unspecified, loopback, ULA, link local, and documentation reverse | RFC 4291, RFC 4193, RFC 3849, RFC 9637 | no |
| `special` | `home.arpa`, `service.arpa`, `resolver.arpa`, `local`, the private use TLDs, and `onion` | RFC 8375, RFC 9665, RFC 9462, RFC 6762, RFC 7686 | no |

## Compatibility and exit codes

Tested on Linux, macOS, and FreeBSD. With no resolver given the tool reads `/etc/resolv.conf`; on macOS that may not reflect a resolver scoped to an interface or VPN, so name it explicitly with `-s` or `@host` when it matters.

The tool exits `0` when every name was handled locally, `1` when any leak or hijack was found, and `2` for a usage or environment error such as an unreachable resolver. Inconclusive and error results do not change the exit code unless you pass `--strict`.

## References

RFC 6303 Locally Served DNS Zones (BCP 163): https://www.rfc-editor.org/rfc/rfc6303
RFC 1918 Address Allocation for Private Internets (BCP 5): https://www.rfc-editor.org/rfc/rfc1918
RFC 3927 Dynamic Configuration of IPv4 Link-Local Addresses: https://www.rfc-editor.org/rfc/rfc3927
RFC 5737 IPv4 Address Blocks Reserved for Documentation: https://www.rfc-editor.org/rfc/rfc5737
RFC 6598 IANA-Reserved IPv4 Prefix for Shared Address Space (BCP 153): https://www.rfc-editor.org/rfc/rfc6598
RFC 7793 Adding 100.64.0.0/10 to the IPv4 Locally-Served DNS Zones Registry: https://www.rfc-editor.org/rfc/rfc7793
RFC 4291 IP Version 6 Addressing Architecture: https://www.rfc-editor.org/rfc/rfc4291
RFC 4193 Unique Local IPv6 Unicast Addresses: https://www.rfc-editor.org/rfc/rfc4193
RFC 3849 IPv6 Address Prefix Reserved for Documentation: https://www.rfc-editor.org/rfc/rfc3849
RFC 9637 Expanding the IPv6 Documentation Space: https://www.rfc-editor.org/rfc/rfc9637
RFC 8375 Special-Use Domain 'home.arpa.': https://www.rfc-editor.org/rfc/rfc8375
RFC 9665 Service Registration Protocol for DNS-Based Service Discovery: https://www.rfc-editor.org/rfc/rfc9665
RFC 9462 Discovery of Designated Resolvers: https://www.rfc-editor.org/rfc/rfc9462
RFC 6762 Multicast DNS: https://www.rfc-editor.org/rfc/rfc6762
RFC 7686 The ".onion" Special-Use Domain Name: https://www.rfc-editor.org/rfc/rfc7686
RFC 7534 AS112 Nameserver Operations: https://www.rfc-editor.org/rfc/rfc7534
RFC 7535 AS112 Redirection Using DNAME: https://www.rfc-editor.org/rfc/rfc7535
RFC 8914 Extended DNS Errors: https://www.rfc-editor.org/rfc/rfc8914

## License

MIT. See LICENSE.
