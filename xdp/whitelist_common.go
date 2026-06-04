package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type whitelistContentHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

type geoCheckOptions struct {
	AssetDir            string
	Address             string
	Mode                string
	ProvinceCSV         string
	WhitelistFile       string
	EgressWhitelistFile string
	JSON                bool
}

func whitelistFileHashes(files []string) ([]whitelistContentHash, error) {
	if len(files) == 0 {
		return nil, nil
	}
	hashes := make([]whitelistContentHash, 0, len(files))
	for _, filePath := range files {
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			continue
		}
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("读取白名单文件失败 (%s): %w", filePath, err)
		}
		sum := sha256.Sum256(content)
		hashes = append(hashes, whitelistContentHash{
			Path: filePath,
			Hash: hex.EncodeToString(sum[:]),
		})
	}
	return hashes, nil
}

func splitFiles(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ":")
	out := parts[:0]
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
