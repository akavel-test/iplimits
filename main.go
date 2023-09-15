package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const testIP = "80.249.99.148"

func main() {
	fmt.Println("hello iplimits")
	// FIXME[LATER]: check if `nft` command exists, else write installation note
	// FIXME[LATER]: check if we're root
	// FIXME[LATER]: ideally, print both above if both are failed, then exit
	// FIXME[LATER]: godoc
	// FIXME[LATER]: gofmt, govet, go test; golint missing docs
	// FIXME[LATER]: --help

	if len(os.Args) > 1 && os.Args[1] == "purge" {
		purgeLimits()
	} else {
		setLimit()
	}
	// TODO: pretty flags for adding limits - try to implement them incrementally:
	// - variable IP
	// - variable packets OR bandwidth limit
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

func setLimit() {
	cmd := exec.Command("nft", "-f-")
	cmd.Stdin = strings.NewReader(filterText)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: setting limit failed: error running nft: %v\n", err)
		fmt.Fprintf(os.Stderr, "error: nft command output:\n%s", string(out))
		os.Exit(1)
	}
}

// FIXME[LATER]: godoc
// See also:
// - https://wiki.nftables.org/wiki-nftables/index.php/Limits
// - https://www.netfilter.org/projects/nftables/manpage.html
// - `nft -a list ruleset`, `nft -f FILE`, `nft delete table NAME`
const filterText = `
	table ip akavel_iplimits {
		chain OUT {
			type filter hook output priority filter; policy accept;
			ip daddr 80.249.99.148 limit rate over 100 kbytes/second drop
		}

		chain IN {
			type filter hook input priority filter; policy accept;
			ip saddr 80.249.99.148 limit rate over 100 kbytes/second drop
		}
	}
`
