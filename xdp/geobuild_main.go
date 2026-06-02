//go:build geobuild

package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if err := runGeoBuildLite(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runGeoBuildLite(args []string) error {
	if len(args) > 0 && args[0] == "__geo-build" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("__geo-build", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var assetDir string
	fs.StringVar(&assetDir, "asset-dir", "", "geo asset output dir")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("__geo-build 不接受额外参数")
	}
	if assetDir == "" {
		return fmt.Errorf("__geo-build 缺少 --asset-dir")
	}
	return buildGeoAssets(geoBuilderOptions{AssetDir: assetDir})
}
