package main

import (
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

type settingsFile struct {
	GitHubHost    string `yaml:"github_host"`
	GitLabHost    string `yaml:"gitlab_host"`
	CloneProtocol string `yaml:"clone_protocol"`
}

var (
	cachedSettings *Settings
	settingsOnce   sync.Once
)

// getSettings returns the merged settings from ~/.config/clones/clones.yml and env vars.
// Precedence (low → high): defaults → file → env vars.
func getSettings() *Settings {
	settingsOnce.Do(func() {
		s := &Settings{
			GitHubHost:    "github.com",
			GitLabHost:    "gitlab.com",
			CloneProtocol: "ssh",
		}

		if dir, err := getConfigDir(); err == nil {
			if data, err := os.ReadFile(filepath.Join(dir, "clones.yml")); err == nil {
				var raw settingsFile
				if err := yaml.Unmarshal(data, &raw); err == nil {
					if raw.GitHubHost != "" {
						s.GitHubHost = raw.GitHubHost
					}
					if raw.GitLabHost != "" {
						s.GitLabHost = raw.GitLabHost
					}
					if raw.CloneProtocol != "" {
						s.CloneProtocol = raw.CloneProtocol
					}
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

		cachedSettings = s
	})
	return cachedSettings
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
