package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const usage = `Usage:
	iplimits purge
	iplimits add IP LIMIT pps|bps|kbps|mbps
`

func main() {
	// FIXME[LATER]: check if `nft` command exists, else write installation note
	// FIXME[LATER]: check if we're root
	// FIXME[LATER]: ideally, print both above if both are failed, then exit
	// FIXME[LATER]: godoc
	// FIXME[LATER]: gofmt, govet, go test; golint missing docs
	// FIXME[LATER]: --help

	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "purge":
		purgeLimits()
	case "add":
		err = addLimit(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q\n%s", cmd, usage)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err)
		os.Exit(1)
	}
}

func purgeLimits() {
	cmd := exec.Command("nft", "delete", "table", tableName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: purging limits failed: error running nft: %v\n", err)
		fmt.Fprintf(os.Stderr, "error: nft command output:\n%s", string(out))
		os.Exit(1)
	}
}

const tableName = "akavel_iplimits"

func addLimit(args []string) error {
	// Verify number of arguments
	if len(args) < 3 {
		return fmt.Errorf("not enough arguments to 'iplimits add'\n%s", usage)
	}

	// Parse arg 0 - IP
	ip, err := netip.ParseAddr(args[0])
	if err != nil {
		return fmt.Errorf("bad IP parameter: %w", err)
	}
	if !ip.Is4() {
		return fmt.Errorf("bad IP parameter: must be IPv4")
	}

	// Parse arg 1 - limit value (without unit)
	rawLimit, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return fmt.Errorf("bad LIMIT parameter: %w", err)
	}
	limit := uint32(rawLimit)

	// Parse arg 2 - limit unit
	unit := rateUnitMap[args[2]]
	if unit == "" {
		return fmt.Errorf("bad limit unit %q", unit)
	}

	cmd := exec.Command("nft", "-f-")
	cmd.Stdin = strings.NewReader(renderFilter(filterVars{
		IP:        ip,
		RateValue: limit,
		RateUnit:  unit,
	}))
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: setting limit failed: error running nft: %v\n", err)
		fmt.Fprintf(os.Stderr, "error: nft command output:\n%s", string(out))
		os.Exit(1)
	}

	return nil
}

func renderFilter(vars filterVars) string {
	vars.Name = tableName
	tmpl := template.Must(template.New("filter").Parse(filterTmpl))
	buf := bytes.NewBuffer(nil)
	err := tmpl.Execute(buf, vars)
	// fmt.Printf("[[\n%s\n]]\n", buf.String())
	if err != nil {
		// FIXME: panic
		panic(fmt.Sprintf("failed to render filter template: %v", err))
	}
	return buf.String()
}

type filterVars struct {
	Name      string
	IP        netip.Addr
	RateValue uint32
	RateUnit  string
}

var rateUnitMap = map[string]string{
	"pps":  "/second",
	"bps":  " bytes/second",
	"kbps": " kbytes/second",
	"mbps": " mbytes/second",
}

// FIXME[LATER]: godoc
// See also:
// - https://wiki.nftables.org/wiki-nftables/index.php/Limits
// - https://www.netfilter.org/projects/nftables/manpage.html
// - `nft -a list ruleset`, `nft -f FILE`, `nft delete table NAME`
const filterTmpl = `
	table ip {{.Name}} {
		chain OUT {
			type filter hook output priority filter; policy accept;
			ip daddr {{.IP}} limit rate over {{.RateValue}}{{.RateUnit}} drop
		}

		chain IN {
			type filter hook input priority filter; policy accept;
			ip saddr {{.IP}} limit rate over {{.RateValue}}{{.RateUnit}} drop
		}
	}
`
