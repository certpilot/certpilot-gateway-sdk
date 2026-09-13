package main

import (
	"crypto/x509/pkix"
	"fmt"
	"os"
)

// A result is one check and what became of it.
type result struct {
	name   string
	state  string // "pass", "fail", "skip"
	detail string
}

// report collects results and prints them once, in the order they ran.
//
// Printed at the end rather than as it goes, so that a gateway author sees the
// whole picture instead of scrolling back through a run that died on the third
// call. The exit status is the machine-readable half.
type report struct{ results []result }

func (r *report) pass(name, format string, args ...any) {
	r.results = append(r.results, result{name, "pass", fmt.Sprintf(format, args...)})
}
func (r *report) fail(name, format string, args ...any) {
	r.results = append(r.results, result{name, "fail", fmt.Sprintf(format, args...)})
}

// note is advisory. It is printed and never fails the run — for things that are
// allowed by the contract but will cost somebody an afternoon.
func (r *report) note(name, format string, args ...any) {
	r.results = append(r.results, result{name, "note", fmt.Sprintf(format, args...)})
}

func (r *report) skip(name, format string, args ...any) {
	r.results = append(r.results, result{name, "skip", fmt.Sprintf(format, args...)})
}

// print writes the report and returns the process exit status.
//
// A skipped check never fails the run. A gateway is allowed not to support
// revocation or CA info, and reporting "not checked" honestly is worth more
// than a green run that quietly tested less than the reader thinks.
func (r *report) print(addr string) int {
	var failed, skipped, noted int
	fmt.Printf("\nprovider.v1 conformance — %s\n\n", addr)
	for _, res := range r.results {
		switch res.state {
		case "pass":
			fmt.Printf("  ok    %-40s %s\n", res.name, res.detail)
		case "note":
			noted++
			fmt.Printf("  note  %-40s %s\n", res.name, res.detail)
		case "skip":
			skipped++
			fmt.Printf("  --    %-40s skipped: %s\n", res.name, res.detail)
		default:
			failed++
			fmt.Printf("  FAIL  %-40s %s\n", res.name, res.detail)
		}
	}

	passed := len(r.results) - failed - skipped - noted
	fmt.Printf("\n%d passed, %d failed, %d skipped, %d advisory\n", passed, failed, skipped, noted)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\nThis gateway does not implement provider.v1 correctly.\n")
		return 1
	}
	if skipped > 0 {
		// Said out loud, because a run that skipped issuance is not evidence
		// that issuance works, and "conformance passed" is exactly how somebody
		// would remember it a week later.
		fmt.Printf("Checks were skipped. This run is not evidence about them.\n")
	}
	return 0
}

func pkixName(commonName string) pkix.Name { return pkix.Name{CommonName: commonName} }

func optional(s string) string {
	if s == "" {
		return ""
	}
	return " — " + s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
