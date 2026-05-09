package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// getConfigDir returns the config directory path
// Checks XDG_CONFIG_HOME environment variable first, falls back to ~/.config/clones
func getConfigDir() (string, error) {
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "clones"), nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not get home directory: %w", err)
	}

	return filepath.Join(homeDir, ".config", "clones"), nil
}

func getConfigPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "exclude.txt"), nil
}

// loadConfig loads the exclude patterns from the config file.
// Returns nil if config doesn't exist (no exclusions).
func loadConfig() (*Config, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{ExcludePatterns: []string{}}, nil
		}
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var patterns []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}

	return &Config{ExcludePatterns: patterns}, nil
}

// shouldExcludeRepo checks if a repository should be excluded based on config patterns.
// Patterns are matched as substrings against: owner/name, platform/owner/name, and description.
func shouldExcludeRepo(repo Repository, config *Config) bool {
	if config == nil || len(config.ExcludePatterns) == 0 {
		return false
	}

	identifiers := []string{
		repo.Owner + "/" + repo.Name,
		repo.Platform + "/" + repo.Owner + "/" + repo.Name,
		repo.Description,
	}

	for _, pattern := range config.ExcludePatterns {
		for _, identifier := range identifiers {
			if strings.Contains(identifier, pattern) {
				return true
			}
		}
	}

	return false
}

func getJiraConfigPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "jira.yml"), nil
}

// jiraConfigFile is the on-disk shape of jira.yml.
// active_statuses accepts either a YAML list or a comma-separated string.
type jiraConfigFile struct {
	Enabled        bool   `yaml:"enabled"`
	Token          string `yaml:"token"`
	BaseURL        string `yaml:"base_url"`
	Email          string `yaml:"email"`
	JQL            string `yaml:"jql"`
	ActiveStatuses any    `yaml:"active_statuses"`
}

// loadJiraConfig loads the Jira configuration from file.
// Returns a zero-valued config if the file doesn't exist.
func loadJiraConfig() (*JiraConfig, error) {
	configPath, err := getJiraConfigPath()
	if err != nil {
		return &JiraConfig{}, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &JiraConfig{}, nil
		}
		return nil, err
	}

	var raw jiraConfigFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", configPath, err)
	}

	config := &JiraConfig{
		Enabled: raw.Enabled,
		Token:   raw.Token,
		BaseURL: raw.BaseURL,
		Email:   raw.Email,
		JQL:     raw.JQL,
	}

	switch v := raw.ActiveStatuses.(type) {
	case nil:
		// not set
	case string:
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				config.ActiveStatuses = append(config.ActiveStatuses, s)
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					config.ActiveStatuses = append(config.ActiveStatuses, s)
				}
			}
		}
	}

	return config, nil
}
