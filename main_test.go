package main

import (
	"net/netip"
	"testing"

	"github.com/kylelemons/godebug/diff"
)

func TestRenderFilter_Full(t *testing.T) {
	want := `
	table ip akavel_iplimits {
		chain OUT {
			type filter hook output priority filter; policy accept;
			ip daddr 1.2.3.4 limit rate over 2 mbytes/second drop
		}

		chain IN {
			type filter hook input priority filter; policy accept;
			ip saddr 1.2.3.4 limit rate over 2 mbytes/second drop
		}
	}
`
	have := renderFilter(filterVars{
		IP:        netip.MustParseAddr("1.2.3.4"),
		RateValue: 2,
		RateUnit:  rateUnitMap["mbps"],
	})
	diff := diff.Diff(have, want)
	if diff != "" {
		t.Error(diff)
	}
}
