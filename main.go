package main

import "fmt"

func main() {
	fmt.Println("hello iplimits")

	// TODO: test setting limit for sample IP by hand via `nft` command
	// TODO: test purging limit for sample IP by hand via `nft` command
	// TODO: write code to set limit from Go - see if it works
	// TODO: if os.Args[1] == 'purge' { purge_all_limits() } - see if it works
	// TODO: pretty flags for adding limits - try to implement them incrementally:
	// - variable IP
	// - variable packets OR bandwidth limit
}
