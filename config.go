package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Runtime config persisted as JSON next to the WARP state.
//
// Precedence: flags > env > config file > generated. The file exists so the
// proxy can start with no environment setup at all, which is what makes a
// dashboard-driven setup possible.
//
// ponytail: plaintext JSON at 0600, not an OS keychain. The secrets are
// PATs the user already pasted by hand; a keychain entry is the upgrade path
// if the file's ACL guarantees ever prove too weak.
type config struct {
	RotateToken       string   `json:"rotateToken,omitempty"`
	RotateURL         string   `json:"rotateUrl,omitempty"`
	GHTokens          []string `json:"ghTokens,omitempty"`
	CodespaceRepo     string   `json:"codespaceRepo,omitempty"`
	CodespaceMachine  string   `json:"codespaceMachine,omitempty"`
	CodespaceFallback bool     `json:"codespaceFallback,omitempty"`
	ProxyUser         string   `json:"proxyUser,omitempty"`
	ProxyPass         string   `json:"proxyPass,omitempty"`
	Laddr             string   `json:"laddr,omitempty"`
	Mode              string   `json:"mode,omitempty"`
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	dir = filepath.Join(dir, "sock2http")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create config directory: %w", err)
	}
	return filepath.Join(dir, "config.json"), nil
}

func loadConfig() config {
	var c config
	path, err := configPath()
	if err != nil {
		return c
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c
	}
	if err := json.Unmarshal(data, &c); err != nil {
		fmt.Fprintf(os.Stderr, "warning: ignoring malformed config %s: %v\n", path, err)
		return config{}
	}
	return c
}

func saveConfig(c config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	// Write-then-rename so a crash cannot leave a truncated config behind.
	tmp, err := os.CreateTemp(filepath.Dir(path), "config-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrPermission) && fileExists(path) {
			return rewriteInPlace(path, data)
		}
		return err
	}
	return nil
}

// rewriteInPlace handles Windows refusing to rename over an existing file.
func rewriteInPlace(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, info.Mode().Perm())
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// applyConfigDefaults fills flags the user did not set from the persisted
// config, so a dashboard-configured install starts with no env vars or flags.
// Explicit flags always win.
func applyConfigDefaults() {
	configMu.RLock()
	c := appConfig
	configMu.RUnlock()

	if c.Mode != "" && os.Getenv("SOCK2HTTP_MODE") == "" {
		// Seed the env so the rest of startup sees the configured mode.
		_ = os.Setenv("SOCK2HTTP_MODE", c.Mode)
	}
	if !flagWasSet("laddr") && c.Laddr != "" {
		*laddr = c.Laddr
	}
	if c.CodespaceRepo != "" && *csRepo == codespaceDefaultRepo {
		*csRepo = c.CodespaceRepo
	}
	if c.CodespaceMachine != "" && *csMachine == codespaceDefaultMachine {
		*csMachine = c.CodespaceMachine
	}
	if *csTokens == "" && len(c.GHTokens) > 0 {
		*csTokens = strings.Join(c.GHTokens, ",")
	}
	if !flagWasSet("cs-fallback") && c.CodespaceFallback {
		*csFallback = true
	}
}

func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
