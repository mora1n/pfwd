package main

import (
	"fmt"
	"os"

	"github.com/mora1n/pfwd/internal/app"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := app.Run(os.Args[1:], app.BuildInfo{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}
}
