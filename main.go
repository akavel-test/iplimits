package main

import "fmt"

const testIP = "80.249.99.148"

func main() {
	fmt.Println("hello iplimits")
	// FIXME[LATER]: check if `nft` command exists, else write installation note
	// FIXME[LATER]: check if we're root
	// FIXME[LATER]: ideally, print both above if both are failed, then exit
	// FIXME[LATER]: godoc
	// FIXME[LATER]: gofmt, govet, go test; golint missing docs

	// TODO: write code to set limit from Go - see if it works
	// TODO: if os.Args[1] == 'purge' { purge_all_limits() } - see if it works
	// TODO: pretty flags for adding limits - try to implement them incrementally:
	// - variable IP
	// - variable packets OR bandwidth limit
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
