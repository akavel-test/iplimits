/*
iplimits is a simple tool for managing per-IP firewall limits in nftables.

iplimits is a simplified CLI interface for the `nft` Linux CLI tool.
It allows adding per-IP transfer rate limits, and clearing any limits
previously set by the tool.

# Requirements

For the tool to work correctly:

  - it must be run with root/superuser privileges;
  - the `nft` CLI tool must be installed and available in $PATH.

# Usage

	iplimits purge
		Clears all limits previously added by iplimits.
	iplimits add IP LIMIT pps|bps|kbps|mbps
		Adds a new download & upload LIMIT for given IP.
		The IP must be in IPv4 format.
		The LIMIT must be an unsigned 32 bit value.
		The limit must be followed by one of the following units:
			pps = packets per second
			bps = bytes per second
			kbps = kilobytes per second
			mbps = megabytes per second
*/
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
		Clears all limits previously added by iplimits.
	iplimits add IP LIMIT pps|bps|kbps|mbps
		Adds a new download & upload LIMIT for given IP.
		The IP must be in IPv4 format.
		The LIMIT must be an unsigned 32 bit value.
		The limit must be followed by one of the following units:
			pps = packets per second
			bps = bytes per second
			kbps = kilobytes per second
			mbps = megabytes per second
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
		err = purgeLimits()
	case "add":
		var args filterArgs
		args, err = parseAddLimitArgs(os.Args[2:])
		if err != nil {
			break
		}
		err = addLimit(args)
	default:
		err = fmt.Errorf("unknown command %q\n%s", cmd, usage)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

const (
	tableName = "akavel_iplimits"
	nft       = "nft"
)

func purgeLimits() error {
	cmd := exec.Command(nft, "delete", "table", tableName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		details := ""
		if len(out) > 0 {
			details = fmt.Sprintf("; output:\n%s", string(out))
		}
		return fmt.Errorf("purging limits failed: error running nft: %w%s", err, details)
	}
	return nil
}

func parseAddLimitArgs(args []string) (filterArgs, error) {
	type res = filterArgs

	// Verify number of arguments
	if len(args) < 3 {
		return res{}, fmt.Errorf("not enough arguments to 'iplimits add'\n%s", usage)
	}

	// Parse arg 0 - IP
	ip, err := netip.ParseAddr(args[0])
	if err != nil {
		return res{}, fmt.Errorf("bad IP parameter: %w", err)
	}
	if !ip.Is4() {
		return res{}, fmt.Errorf("bad IP parameter: must be IPv4")
	}

	// Parse arg 1 - limit value (without unit)
	rawLimit, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return res{}, fmt.Errorf("bad LIMIT parameter: %w", err)
	}
	limit := uint32(rawLimit)

	// Parse arg 2 - limit unit
	unit := rateUnitMap[args[2]]
	if unit == "" {
		return res{}, fmt.Errorf("bad limit unit %q", unit)
	}

	return filterArgs{
		IP:        ip,
		RateValue: limit,
		RateUnit:  unit,
	}, nil
}

func addLimit(args filterArgs) error {
	cmd := exec.Command(nft, "-f-")
	cmd.Stdin = strings.NewReader(renderFilter(args))
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: setting limit failed: error running nft: %v\n", err)
		fmt.Fprintf(os.Stderr, "error: nft command output:\n%s", string(out))
		os.Exit(1)
	}

	return nil
}

func renderFilter(vars filterArgs) string {
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

type filterArgs struct {
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
