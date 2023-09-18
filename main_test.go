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
		// # of args
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
		// IP parameter
		{
			args:          args{"1.2.3.4:8080", "100", "kbps"},
			wantErrPrefix: "bad IP parameter",
		},
		{
			args:          args{"256.256.256.256", "100", "kbps"},
			wantErrPrefix: "bad IP parameter",
		},
		{
			args:          args{"10:10::10", "100", "kbps"},
			wantErrPrefix: "bad IP parameter: must be IPv4",
		},
		// LIMIT parameter
		{
			args:          args{"1.2.3.4", "12e3", "kbps"},
			wantErrPrefix: "bad LIMIT parameter",
		},
		{
			args:          args{"1.2.3.4", "-1", "bps"},
			wantErrPrefix: "bad LIMIT parameter",
		},
		{
			// uint32 max + 1
			args:          args{"1.2.3.4", "4294967296", "bps"},
			wantErrPrefix: `bad LIMIT parameter: strconv.ParseUint: parsing "4294967296": value out of range`,
		},
		// LIMIT unit
		{
			args:          args{"1.2.3.4", "120", "kBps"},
			wantErrPrefix: "bad limit unit",
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
		args args
		want filterArgs
	}{
		{
			// kbps
			args: args{"1.2.3.4", "100", "kbps"},
			want: filterArgs{
				IP:        netip.MustParseAddr("1.2.3.4"),
				RateValue: 100,
				RateUnit:  " kbytes/second",
			},
		},
		{
			// IP max values
			// mbps
			args: args{"255.255.255.255", "1", "mbps"},
			want: filterArgs{
				IP:        netip.MustParseAddr("255.255.255.255"),
				RateValue: 1,
				RateUnit:  " mbytes/second",
			},
		},
		{
			// pps
			args: args{"255.255.255.255", "1", "pps"},
			want: filterArgs{
				IP:        netip.MustParseAddr("255.255.255.255"),
				RateValue: 1,
				RateUnit:  "/second",
			},
		},
		{
			// limit = uint32 max
			// bps
			args: args{"127.0.0.1", "4294967295", "bps"},
			want: filterArgs{
				IP:        netip.MustParseAddr("127.0.0.1"),
				RateValue: 4_294_967_295,
				RateUnit:  " bytes/second",
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
