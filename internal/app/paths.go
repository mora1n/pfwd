package app

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultSocketPath = "/run/pfwd/pfwd.sock"
	defaultDBPath     = "/var/lib/pfwd/pfwd.db"
	defaultInstallBin = "/usr/local/bin/pfwd"
	defaultSystemdDir = "/etc/systemd/system"
)

type Paths struct {
	RootPrefix string
	DBPath     string
	SocketPath string
	BinPath    string
	SystemdDir string
	RunDir     string
	StateDir   string
}

func LoadPaths() Paths {
	root := strings.TrimRight(os.Getenv("PFWD_ROOT_PREFIX"), "/")
	if root == "/" {
		root = ""
	}
	p := Paths{
		RootPrefix: root,
		StateDir:   prefixedPath(root, "var/lib/pfwd"),
		RunDir:     prefixedPath(root, "run/pfwd"),
		BinPath:    prefixedPath(root, "usr/local/bin/pfwd"),
		SystemdDir: prefixedPath(root, "etc/systemd/system"),
	}
	p.DBPath = getenvDefault("PFWD_DB_FILE", filepath.Join(p.StateDir, "pfwd.db"))
	p.SocketPath = getenvDefault("PFWD_SERVICE_SOCKET", filepath.Join(p.RunDir, "pfwd.sock"))
	p.BinPath = getenvDefault("PFWD_BIN_PATH", p.BinPath)
	p.SystemdDir = getenvDefault("PFWD_SYSTEMD_DIR", p.SystemdDir)
	return p
}

func prefixedPath(root, rel string) string {
	if strings.TrimSpace(root) == "" {
		return "/" + rel
	}
	return filepath.Join(root, rel)
}

func getenvDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func dryRun() bool {
	return os.Getenv("PFWD_DRY_RUN") == "1"
}
