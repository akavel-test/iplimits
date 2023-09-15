package main

import (
	"bytes"
	"fmt"
	"html/template"
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
	cmd.Stdin = strings.NewReader(renderFilter())
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: setting limit failed: error running nft: %v\n", err)
		fmt.Fprintf(os.Stderr, "error: nft command output:\n%s", string(out))
		os.Exit(1)
	}
}

func renderFilter() string {
	tmpl := template.Must(template.New("filter").Parse(filterTmpl))
	buf := bytes.NewBuffer(nil)
	err := tmpl.Execute(buf, filterVars{
		Name: tableName,
		IP:   testIP,
		Rate: "100 kbytes/second",
	})
	// fmt.Printf("[[\n%s\n]]\n", buf.String())
	if err != nil {
		// FIXME: panic
		panic(fmt.Sprintf("failed to render filter template: %v", err))
	}
	return buf.String()
}

type filterVars struct {
	Name string
	IP   string // FIXME[LATER]: use netip.Addr ?
	Rate string // FIXME[LATER]: split?
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
			ip daddr {{.IP}} limit rate over {{.Rate}} drop
		}

		chain IN {
			type filter hook input priority filter; policy accept;
			ip saddr {{.IP}} limit rate over {{.Rate}} drop
		}
	}
`
