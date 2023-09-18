
iplimits is a simple tool for managing per-IP firewall limits in nftables.

iplimits is a simplified CLI interface for the `nft` Linux CLI tool.
It allows adding per-IP transfer rate limits, and clearing any limits
previously set by the tool.

# Requirements

For the tool to work correctly:

  - it must be run with root/superuser privileges;
  - the `nft` CLI tool must be installed and available in $PATH;
  - the Go compiler toolchain must be installed and available in $PATH.

# Installation

To install, run the following command:

	go install github.com/akavel/homework230913

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
