// Package cli wires the command line surface to the runner and report packages.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/farrokhi/localzone-leaktest/internal/classify"
	"github.com/farrokhi/localzone-leaktest/internal/dataset"
	"github.com/farrokhi/localzone-leaktest/internal/report"
	"github.com/farrokhi/localzone-leaktest/internal/runner"
)

type flags struct {
	server      string
	port        int
	category    string
	ipv4        bool
	ipv6        bool
	json        bool
	list        bool
	timeout     int
	tries       int
	verbose     bool
	quiet       bool
	noColor     bool
	strict      bool
	concurrency int
}

// Execute runs the command line tool and returns the process exit code:
// 0 when every tested name stayed local, 1 when any leak or hijack was found,
// and 2 for usage or environment errors.
func Execute(version string) int {
	var exit int
	f := &flags{}
	cmd := newRootCmd(version, f, &exit)
	if err := cmd.Execute(); err != nil {
		return 2
	}
	return exit
}

func newRootCmd(version string, f *flags, exit *int) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "localzone-leaktest [@server] [flags]",
		Short: "Check whether a DNS resolver leaks locally served and special use zones",
		Long: "localzone-leaktest checks whether a DNS resolver answers the IANA locally\n" +
			"served zones and special use names locally (RFC 6303 and related), or whether\n" +
			"it leaks those queries to the public internet. It is not a VPN DNS leak test.",
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       version,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, f, exit)
		},
	}

	cmd.Flags().StringVarP(&f.server, "server", "s", "", "resolver to test (host, IPv4/IPv6, or @host); default system resolver")
	cmd.Flags().IntVarP(&f.port, "port", "p", 0, "resolver port (default 53)")
	cmd.Flags().StringVarP(&f.category, "category", "c", "all", "comma separated category filter: rfc1918,ip4special,ip6,special,all")
	cmd.Flags().BoolVarP(&f.ipv4, "ipv4", "4", false, "force IPv4 transport to the resolver")
	cmd.Flags().BoolVarP(&f.ipv6, "ipv6", "6", false, "force IPv6 transport to the resolver")
	cmd.Flags().BoolVarP(&f.json, "json", "j", false, "emit machine readable JSON")
	cmd.Flags().BoolVarP(&f.list, "list", "l", false, "list the test names and exit without querying")
	cmd.Flags().IntVarP(&f.timeout, "timeout", "t", 2, "per query timeout in seconds")
	cmd.Flags().IntVar(&f.tries, "tries", 1, "per query attempt count")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "show raw signal detail per name")
	cmd.Flags().BoolVarP(&f.quiet, "quiet", "q", false, "print only the summary")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false, "disable ANSI color")
	cmd.Flags().BoolVar(&f.strict, "strict", false, "treat INCONCLUSIVE results as a non-zero exit for CI")
	cmd.Flags().IntVar(&f.concurrency, "concurrency", 10, "number of parallel probes")

	// Pre-register the version flag so it carries a -V shorthand; cobra keeps its
	// own handling since a "version" flag already exists.
	cmd.Flags().BoolP("version", "V", false, "print version and exit")

	cmd.SetVersionTemplate("localzone-leaktest {{.Version}}\n")
	return cmd
}

func run(cmd *cobra.Command, args []string, f *flags, exit *int) error {
	// A leading @ is accepted on both the -s value and the positional argument.
	server := strings.TrimPrefix(f.server, "@")
	if len(args) == 1 {
		arg := args[0]
		if !strings.HasPrefix(arg, "@") {
			return fmt.Errorf("unexpected argument %q; a resolver must be given as @host or with -s", arg)
		}
		server = strings.TrimPrefix(arg, "@")
	}

	if f.ipv4 && f.ipv6 {
		return fmt.Errorf("-4 and -6 are mutually exclusive")
	}

	cats, err := parseCategories(f.category)
	if err != nil {
		return err
	}

	if f.list {
		return writeList(cmd.OutOrStdout(), cats)
	}

	net := "udp"
	if f.ipv4 {
		net = "udp4"
	} else if f.ipv6 {
		net = "udp6"
	}

	rep, err := runner.Run(runner.Options{
		Server:      server,
		Port:        f.port,
		Net:         net,
		Categories:  cats,
		Timeout:     time.Duration(f.timeout) * time.Second,
		Tries:       f.tries,
		Concurrency: f.concurrency,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		*exit = 2
		return nil
	}

	if f.json {
		if err := report.JSON(os.Stdout, rep); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			*exit = 2
			return nil
		}
	} else {
		opts := report.Options{
			Color:   !f.noColor && isTTY(os.Stdout),
			Verbose: f.verbose,
			Quiet:   f.quiet,
		}
		if err := report.Human(os.Stdout, rep, opts); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			*exit = 2
			return nil
		}
	}

	*exit = exitCode(rep.Summary, f.strict)
	return nil
}

// exitCode maps a run summary to the process exit code: 2 when nothing could be
// tested (every name errored, for example an unreachable resolver), 1 when any
// leak or hijack was found or when --strict and an inconclusive result is
// present, and 0 otherwise.
func exitCode(s runner.Summary, strict bool) int {
	if s.Total > 0 && s.Counts[classify.VerdictError] == s.Total {
		return 2
	}
	if s.Leaks > 0 {
		return 1
	}
	if strict && s.Counts[classify.VerdictInconclusive] > 0 {
		return 1
	}
	return 0
}

func parseCategories(list string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(list, ",") {
		key := strings.TrimSpace(part)
		if key == "" {
			continue
		}
		if !dataset.ValidCategory(key) {
			return nil, fmt.Errorf("unknown category %q (valid: %s, all)", key, strings.Join(dataset.Categories(), ", "))
		}
		out = append(out, key)
	}
	if len(out) == 0 {
		return []string{"all"}, nil
	}
	return out, nil
}

// writeList prints the selected test names. The tabwriter only buffers, so
// Flush carries the one real write error.
func writeList(w io.Writer, cats []string) error {
	zones := dataset.Filter(dataset.Build(), cats)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tCATEGORY\tRFC\tAS112")
	for _, z := range zones {
		as112 := "no"
		if z.AS112 {
			as112 = "yes"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", z.Name, z.Category, z.RFC, as112)
	}
	return tw.Flush()
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
