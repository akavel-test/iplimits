package main

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/diff"
)

func TestRenderFilter(t *testing.T) {
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
	have := renderFilter(filterArgs{
		IP:        netip.MustParseAddr("1.2.3.4"),
		RateValue: 2,
		RateUnit:  rateUnitMap["mbps"],
	})
	diff := diff.Diff(have, want)
	if diff != "" {
		t.Error(diff)
	}
}

func TestParseAddLimitArgs_Invalid(t *testing.T) {
	type args []string
	tests := []struct {
		args          args
		wantErrPrefix string
	}{
		{
			args:          args{},
			wantErrPrefix: "not enough arguments",
		},
		{
			args:          args{"1.2.3.4"},
			wantErrPrefix: "not enough arguments",
		},
		{
			args:          args{"1.2.3.4", "100"},
			wantErrPrefix: "not enough arguments",
		},
	}

	for _, tt := range tests {
		_, err := parseAddLimitArgs(tt.args)
		errText := fmt.Sprintf("%s", err)
		if !strings.HasPrefix(errText, tt.wantErrPrefix) {
			t.Errorf("%q: bad error:\nwant: %s...\nhave: %s",
				tt.args, tt.wantErrPrefix, errText)
		}
	}
}

func TestParseAddLimitArgs_OK(t *testing.T) {
	type args []string
	tests := []struct {
		comment string
		args    args
		want    filterArgs
	}{
		{
			comment: "",
			args:    args{"1.2.3.4", "100", "kbps"},
			want: filterArgs{
				IP:        netip.MustParseAddr("1.2.3.4"),
				RateValue: 100,
				RateUnit:  " kbytes/second",
			},
		},
	}

	for _, tt := range tests {
		have, err := parseAddLimitArgs(tt.args)
		if err != nil {
			t.Errorf("%q: unexpected error: %s",
				tt.args, err)
		}
		if have != tt.want {
			t.Errorf("%q: bad result:\nhave: %v\nwant: %v",
				tt.args, have, tt.want)
		}
	}
}
