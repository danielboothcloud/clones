package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type settingsFile struct {
	GitHubHost    string            `yaml:"github_host"`
	GitLabHost    string            `yaml:"gitlab_host"`
	CloneProtocol string            `yaml:"clone_protocol"`
	CloneRoot     string            `yaml:"clone_root"`
	Remote        *remoteConfigFile `yaml:"remote"`
}

type remoteConfigFile struct {
	Host               string   `yaml:"host"`
	Path               string   `yaml:"path"`
	Ops                []string `yaml:"ops"`
	SyncTimeoutSeconds int      `yaml:"sync_timeout_seconds"`
}

// validRemoteOps lists every operation name that can appear in remote.ops.
// Anything else is rejected at startup so typos fail loudly instead of silently
// no-op'ing.
var validRemoteOps = map[string]bool{
	"clone":    true,
	"delete":   true,
	"pull":     true,
	"push":     true,
	"checkout": true,
}

var (
	cachedSettings *Settings
	settingsOnce   sync.Once
)

// getSettings returns the merged settings from ~/.config/clones/clones.yml and env vars.
// Precedence (low → high): defaults → file → env vars.
//
// On invalid configuration (bad remote.path, unknown op, etc.) it prints to stderr
// and exits — bad config should fail loudly at startup, not produce confusing behavior later.
func getSettings() *Settings {
	settingsOnce.Do(func() {
		s := &Settings{
			GitHubHost:    "github.com",
			GitLabHost:    "gitlab.com",
			CloneProtocol: "ssh",
			CloneRoot:     defaultCloneRoot(),
		}

		if dir, err := getConfigDir(); err == nil {
			configPath := filepath.Join(dir, "clones.yml")
			if data, err := os.ReadFile(configPath); err == nil {
				var raw settingsFile
				if err := yaml.Unmarshal(data, &raw); err != nil {
					fmt.Fprintf(os.Stderr, "✗ Failed to parse %s: %v\n", configPath, err)
					os.Exit(1)
				}
				if raw.GitHubHost != "" {
					s.GitHubHost = raw.GitHubHost
				}
				if raw.GitLabHost != "" {
					s.GitLabHost = raw.GitLabHost
				}
				if raw.CloneProtocol != "" {
					s.CloneProtocol = raw.CloneProtocol
				}
				if raw.CloneRoot != "" {
					s.CloneRoot = expandTilde(raw.CloneRoot)
				}
				if raw.Remote != nil {
					if err := validateRemote(raw.Remote); err != nil {
						fmt.Fprintf(os.Stderr, "✗ Invalid remote config in %s: %v\n", configPath, err)
						os.Exit(1)
					}
					if len(raw.Remote.Ops) > 0 {
						timeout := raw.Remote.SyncTimeoutSeconds
						if timeout <= 0 {
							timeout = 5
						}
						s.Remote = &RemoteConfig{
							Host:               raw.Remote.Host,
							Path:               raw.Remote.Path,
							Ops:                raw.Remote.Ops,
							SyncTimeoutSeconds: timeout,
						}
					}
					// remote: present but ops empty → leave Remote nil (config is parked but inactive).
				}
			}
		}

		if v := os.Getenv("GITHUB_HOST"); v != "" {
			s.GitHubHost = v
		}
		if v := os.Getenv("GITLAB_HOST"); v != "" {
			s.GitLabHost = v
		}
		if v := os.Getenv("CLONES_PROTOCOL"); v != "" {
			s.CloneProtocol = v
		}
		if v := os.Getenv("CLONES_ROOT"); v != "" {
			s.CloneRoot = expandTilde(v)
		}

		cachedSettings = s
	})
	return cachedSettings
}

// validateRemote enforces the rules documented in CLAUDE.md / README:
// host must be set, path must be absolute (no tilde, no relative), every op must be known.
func validateRemote(r *remoteConfigFile) error {
	if strings.TrimSpace(r.Host) == "" {
		return fmt.Errorf("remote.host is required")
	}
	if r.Path == "" {
		return fmt.Errorf("remote.path is required")
	}
	if strings.HasPrefix(r.Path, "~") {
		return fmt.Errorf("remote.path must be absolute (no tilde) — the local user's home isn't the remote user's home")
	}
	if !strings.HasPrefix(r.Path, "/") {
		return fmt.Errorf("remote.path must be absolute, got %q", r.Path)
	}
	for _, op := range r.Ops {
		if !validRemoteOps[op] {
			return fmt.Errorf("unknown remote.ops entry %q (valid: clone, delete, pull, push, checkout)", op)
		}
	}
	return nil
}

// defaultCloneRoot returns ~/projects, falling back to "./projects" if
// the home directory can't be resolved (which is essentially never on a real system).
func defaultCloneRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "projects"
	}
	return filepath.Join(home, "projects")
}

// expandTilde resolves a leading "~" or "~/" to the user's home directory.
// Returns the input unchanged when home can't be resolved.
func expandTilde(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// cloneURL picks the right clone URL for a repo based on configured protocol.
// Falls back to whichever URL is populated if the preferred one is empty.
func cloneURL(repo *Repository) string {
	if getSettings().CloneProtocol == "https" && repo.HTTPSURL != "" {
		return repo.HTTPSURL
	}
	if repo.URL != "" {
		return repo.URL
	}
	return repo.HTTPSURL
}
