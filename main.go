package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nutsdb/nutsdb"
)

type Repository struct {
	Platform    string
	Owner       string
	Name        string
	URL         string
	Language    string
	Stars       int
	Description string
	LocalPath   string // Only populated for local repos
	IsDirty     bool   // True if local repo has uncommitted changes
	HasUnpushed bool   // True if local repo has unpushed commits

	// Jira integration fields
	CurrentBranch       string   // Current branch name (for local repos)
	JiraTicketID        string   // Extracted ticket ID (e.g., "PROJ-123") - primary ticket
	JiraTicketIDs       []string // All ticket IDs found in branches
	JiraStatus          string   // Ticket status from Jira API
	JiraSummary         string   // Ticket summary/title
	HasActiveJiraTicket bool     // True if ticket is in active state
}

type CliArgs struct {
	LocalMode  bool
	RemoteOnly bool
	Platform   string // "github", "gitlab", or "" for all
	Filter     string
	NoCache    bool // Bypass cache and fetch fresh data from APIs
	JiraFilter bool // Filter repos with active Jira tickets
}

// Config holds user configuration for excluding repositories
type Config struct {
	ExcludePatterns []string // Patterns to exclude (substrings matching owner/name or description)
}

// JiraConfig holds user configuration for Jira integration
type JiraConfig struct {
	Enabled        bool     // Whether Jira integration is enabled (default: false)
	Token          string   // API token (can also use JIRA_API_TOKEN env var)
	BaseURL        string   // Base URL (can also use JIRA_BASE_URL env var)
	Email          string   // User email for currentUser() resolution (optional)
	JQL            string   // JQL query to filter tickets (e.g., "assignee = currentUser() AND status not in (Closed, Done)")
	ActiveStatuses []string // Custom list of active statuses (if not set, uses defaults)
}

// HTTP client singleton for connection pooling
var (
	sharedHTTPClient *http.Client
	clientOnce       sync.Once
)

func getHTTPClient() *http.Client {
	clientOnce.Do(func() {
		transport := &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		}
		sharedHTTPClient = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	})
	return sharedHTTPClient
}

// Token caching
var (
	githubToken     string
	gitlabToken     string
	jiraToken       string
	jiraBaseURL     string
	githubTokenOnce sync.Once
	gitlabTokenOnce sync.Once
	jiraConfigOnce  sync.Once
)

func getGitHubToken() string {
	githubTokenOnce.Do(func() {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GITHUB_ACCESS_TOKEN")
		}
		if token == "" {
			homeDir, _ := os.UserHomeDir()
			data, err := os.ReadFile(filepath.Join(homeDir, ".config", "gh", "hosts.yml"))
			if err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "oauth_token:") {
						token = strings.TrimSpace(strings.TrimPrefix(line, "oauth_token:"))
						break
					}
				}
			}
		}
		githubToken = token
	})
	return githubToken
}

func getGitLabToken() string {
	gitlabTokenOnce.Do(func() {
		token := os.Getenv("GITLAB_TOKEN")
		if token == "" {
			token = os.Getenv("GITLAB_ACCESS_TOKEN")
		}
		if token == "" {
			homeDir, _ := os.UserHomeDir()
			data, err := os.ReadFile(filepath.Join(homeDir, ".config", "glab-cli", "config.yml"))
			if err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "token:") {
						token = strings.TrimSpace(strings.TrimPrefix(line, "token:"))
						break
					}
				}
			}
		}
		gitlabToken = token
	})
	return gitlabToken
}

// getJiraConfig loads Jira configuration from environment variables or config file
func getJiraConfig() (token, baseURL, email string) {
	jiraConfigOnce.Do(func() {
		// Try environment variables first
		jiraToken = os.Getenv("JIRA_API_TOKEN")
		jiraBaseURL = os.Getenv("JIRA_BASE_URL")

		// Always load config file to get email and fallback values
		config, _ := loadJiraConfig()
		if config != nil {
			if jiraToken == "" && config.Token != "" {
				jiraToken = config.Token
			}
			if jiraBaseURL == "" && config.BaseURL != "" {
				jiraBaseURL = config.BaseURL
			}
			email = config.Email
		}
	})
	return jiraToken, jiraBaseURL, email
}

// ============================================================================
// NutsDB Caching Layer
// ============================================================================

// Database singleton for repository caching
var (
	cacheDB *nutsdb.DB
	dbOnce  sync.Once
)

const (
	cacheTTLHours = 24
	bucketGitHub  = "github_repos"
	bucketGitLab  = "gitlab_repos"
	bucketMeta    = "metadata"
)

// getCacheDB opens and returns the NutsDB database (singleton pattern)
func getCacheDB() (*nutsdb.DB, error) {
	var dbErr error
	dbOnce.Do(func() {
		cacheDir, err := getCacheDir()
		if err != nil {
			dbErr = fmt.Errorf("failed to get cache dir: %w", err)
			return
		}

		dbPath := filepath.Join(cacheDir, "db")
		if err := os.MkdirAll(dbPath, 0755); err != nil {
			dbErr = fmt.Errorf("failed to create db directory: %w", err)
			return
		}

		options := nutsdb.DefaultOptions
		options.Dir = dbPath
		options.SegmentSize = 256 * 1024 * 1024 // 256MB
		options.EnableHintFile = true
		options.EnableMergeV2 = true

		cacheDB, dbErr = nutsdb.Open(options)
		if dbErr != nil {
			dbErr = fmt.Errorf("failed to open cache db: %w", dbErr)
		}
	})
	return cacheDB, dbErr
}

// serializeRepo converts Repository struct to JSON bytes
func serializeRepo(repo Repository) ([]byte, error) {
	return json.Marshal(repo)
}

// deserializeRepo converts JSON bytes to Repository struct
func deserializeRepo(data []byte) (Repository, error) {
	var repo Repository
	err := json.Unmarshal(data, &repo)
	return repo, err
}

// loadReposFromDB loads cached repositories from NutsDB for given platform
func loadReposFromDB(platform string) []Repository {
	db, err := getCacheDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not open cache db: %v\n", err)
		return []Repository{}
	}

	tx, err := db.Begin(false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not begin tx: %v\n", err)
		return []Repository{}
	}
	defer tx.Rollback()

	var bucket string
	if platform == "github" {
		bucket = bucketGitHub
	} else if platform == "gitlab" {
		bucket = bucketGitLab
	} else {
		return []Repository{}
	}

	var repos []Repository
	_, entries, err := tx.GetAll(bucket)
	if err != nil {
		return []Repository{}
	}

	for _, value := range entries {
		if repo, err := deserializeRepo(value); err == nil {
			repos = append(repos, repo)
		}
	}

	return repos
}

// saveReposToDB saves repositories to NutsDB for given platform (upsert)
func saveReposToDB(platform string, repos []Repository) error {

	db, err := getCacheDB()
	if err != nil {
		return fmt.Errorf("could not open cache db: %w", err)
	}

	tx, err := db.Begin(true)
	if err != nil {
		return fmt.Errorf("could not begin tx: %w", err)
	}

	var bucket string
	if platform == "github" {
		bucket = bucketGitHub
	} else if platform == "gitlab" {
		bucket = bucketGitLab
	} else {
		tx.Rollback()
		return fmt.Errorf("unknown platform: %s", platform)
	}

	// Create buckets on first save (NutsDB pattern)
	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucket); err != nil {
		if !strings.Contains(err.Error(), "bucket already exists") && !strings.Contains(err.Error(), "already exist") {
			tx.Rollback()
			return fmt.Errorf("failed to create bucket %s: %w", bucket, err)
		}
	}
	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucketMeta); err != nil {
		if !strings.Contains(err.Error(), "bucket already exists") && !strings.Contains(err.Error(), "already exist") {
			tx.Rollback()
			return fmt.Errorf("failed to create bucket %s: %w", bucketMeta, err)
		}
	}

	for _, repo := range repos {
		key := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)
		value, err := serializeRepo(repo)
		if err != nil {
			continue
		}
		_ = tx.Put(bucket, []byte(key), value, 0)
	}

	timestampKey := fmt.Sprintf("%s:batch_timestamp", platform)
	_ = tx.Put(bucketMeta, []byte(timestampKey), []byte(fmt.Sprintf("%d", time.Now().Unix())), 0)

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("could not commit tx: %w", err)
	}

	return nil
}

// isBatchFresh checks if cached data is still valid (not expired)
func isBatchFresh(platform string) bool {
	db, err := getCacheDB()
	if err != nil {
		return false
	}

	tx, err := db.Begin(false)
	if err != nil {
		return false
	}
	defer tx.Rollback()

	timestampKey := fmt.Sprintf("%s:batch_timestamp", platform)
	value, err := tx.Get(bucketMeta, []byte(timestampKey))
	if err != nil {
		return false
	}

	timestamp, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return false
	}

	expiresAt := time.Unix(timestamp, 0).Add(time.Duration(cacheTTLHours) * time.Hour)
	isFresh := time.Now().Before(expiresAt)
	return isFresh
}

// isBatchStale checks if cached data exists but is expired
func isBatchStale(platform string) bool {
	db, err := getCacheDB()
	if err != nil {
		return false
	}

	tx, err := db.Begin(false)
	if err != nil {
		return false
	}
	defer tx.Rollback()

	timestampKey := fmt.Sprintf("%s:batch_timestamp", platform)
	value, err := tx.Get(bucketMeta, []byte(timestampKey))
	if err != nil {
		return false
	}

	timestamp, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return false
	}

	expiresAt := time.Unix(timestamp, 0).Add(time.Duration(cacheTTLHours) * time.Hour)
	return time.Now().After(expiresAt)
}

// getCacheDir returns the cache directory path, creating it if needed
func getCacheDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, ".cache", "clones")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("could not create cache directory: %w", err)
	}

	return cacheDir, nil
}

// getConfigDir returns the config directory path
// Checks XDG_CONFIG_HOME environment variable first, falls back to ~/.config/clones
func getConfigDir() (string, error) {
	// Check XDG_CONFIG_HOME first
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "clones"), nil
	}

	// Fall back to ~/.config/clones
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".config", "clones")
	return configDir, nil
}

// getConfigPath returns the config file path
func getConfigPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "exclude.txt"), nil
}

// loadConfig loads the exclude patterns from the config file
// Returns nil if config doesn't exist (no exclusions)
func loadConfig() (*Config, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, err
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file means no exclusions
			return &Config{ExcludePatterns: []string{}}, nil
		}
		return nil, err
	}

	// Parse file - one pattern per line, ignore comments and empty lines
	lines := strings.Split(string(data), "\n")
	var patterns []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}

	return &Config{ExcludePatterns: patterns}, nil
}

// shouldExcludeRepo checks if a repository should be excluded based on config patterns
// Patterns are matched as substrings against: owner/name, platform/owner/name, and description
func shouldExcludeRepo(repo Repository, config *Config) bool {
	if config == nil || len(config.ExcludePatterns) == 0 {
		return false
	}

	// Check patterns against various repo identifiers
	identifiers := []string{
		repo.Owner + "/" + repo.Name,                       // "owner/repo"
		repo.Platform + "/" + repo.Owner + "/" + repo.Name, // "github/owner/repo"
		repo.Description,                                   // description text
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

// getJiraConfigPath returns the Jira config file path
func getJiraConfigPath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "jira.yml"), nil
}

// loadJiraConfig loads the Jira configuration from file
// Returns nil if config doesn't exist (uses defaults)
func loadJiraConfig() (*JiraConfig, error) {
	configPath, err := getJiraConfigPath()
	if err != nil {
		return &JiraConfig{JQL: "", ActiveStatuses: nil}, nil
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file means use defaults
			return &JiraConfig{JQL: "", ActiveStatuses: nil}, nil
		}
		return nil, err
	}

	config := &JiraConfig{JQL: "", ActiveStatuses: nil}

	// Parse YAML-like format (simple key=value parsing)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key: value format
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(strings.Trim(parts[1], `"'`))

				switch key {
				case "enabled":
				config.Enabled = strings.ToLower(value) == "true"
			case "token":
					config.Token = value
				case "base_url":
					config.BaseURL = value
				case "email":
					config.Email = value
				case "jql":
					config.JQL = value
				case "active_statuses":
					// Parse comma-separated list
					statuses := strings.Split(value, ",")
					for i, s := range statuses {
						statuses[i] = strings.TrimSpace(s)
					}
					config.ActiveStatuses = statuses
				}
			}
		}
	}

	return config, nil
}

func parseArgs() CliArgs {
	args := CliArgs{}
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprintf(os.Stderr, `clone - Interactive Repository Cloning and Management Tool

USAGE:
  clone [OPTIONS] [FILTER]

OPTIONS:
  -l, --local            Browse and manage only local repositories
  -r, --remote           Browse only remote repositories (exclude local)
  --platform <name>      Filter by platform: github or gitlab
  --jira                 Show only repos with active Jira tickets
  --no-cache             Bypass cache and fetch fresh data from APIs
  -h, --help             Show this help message

EXAMPLES:
  clone                        # Browse all repos (remote + local merged)
  clone terraform              # Filter repos by "terraform"
  clone -l                     # Browse only local repos
  clone -r                     # Browse only remote repos
  clone --platform gitlab      # Only GitLab repos (skips GitHub API)
  clone -l --platform gitlab   # Only local GitLab repos
  clone --jira                 # Only repos with active Jira tickets
  clone -l --jira              # Only local repos with active Jira tickets
  clone --no-cache             # Force refresh from APIs (bypass cache)

For more information, see the README.md
`)
			os.Exit(0)
		} else if arg == "-l" || arg == "--local" {
			args.LocalMode = true
		} else if arg == "-r" || arg == "--remote" {
			args.RemoteOnly = true
		} else if arg == "--no-cache" {
			args.NoCache = true
		} else if arg == "--platform" {
			// Next arg should be the platform name
			if i+1 < len(os.Args) {
				i++
				platform := strings.ToLower(os.Args[i])
				if platform == "github" || platform == "gitlab" {
					args.Platform = platform
				} else {
					fmt.Fprintf(os.Stderr, "✗ Invalid platform: %s (must be 'github' or 'gitlab')\n", os.Args[i])
					os.Exit(1)
				}
			} else {
				fmt.Fprintf(os.Stderr, "✗ --platform requires an argument (github or gitlab)\n")
				os.Exit(1)
			}
		} else if arg == "--jira" {
			args.JiraFilter = true
		} else if !strings.HasPrefix(arg, "-") {
			args.Filter = arg
		}
	}
	return args
}

// ============================================================================
// Local Repository Management
// ============================================================================

// extractRepoFromPath extracts owner and name from a repository path
// GitHub: ~/projects/work/octocat/Hello-World -> owner="octocat", name="Hello-World"
// GitLab: ~/projects/work/a/b/c/d/repo -> owner="a/b/c/d", name="repo"
func extractRepoFromPath(repoPath string, workDir string) (owner string, name string) {
	// Get relative path from work directory
	relPath, err := filepath.Rel(workDir, repoPath)
	if err != nil {
		return "", ""
	}

	parts := strings.Split(relPath, string(filepath.Separator))
	if len(parts) < 2 {
		return "", ""
	}

	// Last part is repository name
	name = parts[len(parts)-1]
	// Everything before that is the owner (handles GitLab nested groups)
	owner = strings.Join(parts[:len(parts)-1], "/")

	return owner, name
}

// getRemoteInfo gets remote URL from git config and detects platform
func getRemoteInfo(repoPath string) (url string, platform string) {
	cmd := exec.Command("git", "config", "--get", "remote.origin.url")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return "", "git"
	}

	url = strings.TrimSpace(string(output))

	// Detect platform from URL
	if strings.Contains(url, "github.com") {
		platform = "github"
	} else if strings.Contains(url, "gitlab.com") {
		platform = "gitlab"
	} else {
		platform = "git"
	}

	return url, platform
}

// getRepoDescription tries to get a description from README or git config
func getRepoDescription(repoPath string) string {
	// Try README first line
	readmePaths := []string{"README.md", "README", "readme.md", "readme"}
	for _, readme := range readmePaths {
		readmePath := filepath.Join(repoPath, readme)
		data, err := os.ReadFile(readmePath)
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				// Skip empty lines and markdown headers
				if line != "" && !strings.HasPrefix(line, "#") {
					return line
				}
			}
		}
	}

	// Fallback to git config description
	cmd := exec.Command("git", "config", "--get", "description")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err == nil {
		desc := strings.TrimSpace(string(output))
		if desc != "" && desc != "Unnamed repository; edit this file 'description' to name the repository." {
			return desc
		}
	}

	return ""
}

// matchesFilter checks if a repository matches the filter string
func matchesFilter(repo *Repository, filter string) bool {
	if filter == "" {
		return true
	}

	filter = strings.ToLower(filter)
	return strings.Contains(strings.ToLower(repo.Owner), filter) ||
		strings.Contains(strings.ToLower(repo.Name), filter) ||
		strings.Contains(strings.ToLower(repo.Description), filter)
}

// isRepoDirty checks if a repository has uncommitted changes
func isRepoDirty(repoPath string) bool {
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	// If output is not empty, there are uncommitted changes
	return len(strings.TrimSpace(string(output))) > 0
}

// hasUnpushedCommits checks if a repository has commits that haven't been pushed
func hasUnpushedCommits(repoPath string) bool {
	// Check if there's an upstream branch
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "@{u}")
	cmd.Dir = repoPath
	if err := cmd.Run(); err != nil {
		// No upstream branch configured
		return false
	}

	// Check for commits in HEAD that aren't in upstream
	cmd = exec.Command("git", "log", "@{u}..HEAD", "--oneline")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	// If output is not empty, there are unpushed commits
	return len(strings.TrimSpace(string(output))) > 0
}

// ============================================================================
// Jira Integration
// ============================================================================

// Jira ticket pattern: PROJECT-123 (case insensitive: letters, hyphen, numbers)
var jiraTicketRegex = regexp.MustCompile(`(?i)[a-z]+-\d+`)

// extractJiraTicketID extracts Jira ticket ID from branch name
// Supports formats: "PROJ-123-feature", "feature/PROJ-123", "PROJ-123"
func extractJiraTicketID(branch string) string {
	// Remove common prefixes
	branch = strings.TrimPrefix(branch, "feature/")
	branch = strings.TrimPrefix(branch, "bugfix/")
	branch = strings.TrimPrefix(branch, "hotfix/")
	branch = strings.TrimPrefix(branch, "release/")

	// Split by common delimiters
	parts := strings.Split(branch, "/")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Check if this part matches Jira ticket pattern
		if jiraTicketRegex.MatchString(part) {
			return part
		}
		// Also check if part starts with ticket pattern
		if matches := jiraTicketRegex.FindString(part); matches != "" {
			return matches
		}
	}

	return ""
}

// getCurrentBranch gets the current branch name for a local repository
func getCurrentBranch(repoPath string) string {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// getAllBranches gets all branch names for a local repository
func getAllBranches(repoPath string) []string {
	cmd := exec.Command("git", "branch", "-a", "--format=%(refname:short)")
	cmd.Dir = repoPath
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	branches := strings.Split(strings.TrimSpace(string(output)), "\n")
	var result []string
	seen := make(map[string]bool)

	for _, branch := range branches {
		branch = strings.TrimSpace(branch)
		if branch == "" || branch == "HEAD" {
			continue
		}
		// Strip origin/ prefix for deduplication
		displayBranch := strings.TrimPrefix(branch, "origin/")
		if !seen[displayBranch] {
			seen[displayBranch] = true
			result = append(result, displayBranch)
		}
	}

	return result
}

// JiraTicket represents a Jira ticket from the API
type JiraTicket struct {
	Key    string `json:"key"`
	Fields struct {
		Summary string `json:"summary"`
		Status  struct {
			Name string `json:"name"`
		} `json:"status"`
	} `json:"fields"`
}

// Jira ticket cache to avoid redundant API calls
var (
	jiraCache   = make(map[string]*JiraTicket)
	jiraCacheMu sync.RWMutex
)

// fetchJiraTicket fetches ticket information from Jira API with caching
func fetchJiraTicket(ticketID string) *JiraTicket {
	// Check cache first
	jiraCacheMu.RLock()
	if cached, exists := jiraCache[ticketID]; exists {
		jiraCacheMu.RUnlock()
		return cached
	}
	jiraCacheMu.RUnlock()

	token, baseURL, email := getJiraConfig()
	if token == "" || baseURL == "" {
		return nil
	}

	// Build API URL: https://example.atlassian.net/rest/api/3/issue/PROJ-123
	url := fmt.Sprintf("%s/rest/api/3/issue/%s",
		strings.TrimSuffix(baseURL, "/"), ticketID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	// Jira Cloud API requires Basic auth with email and API token
	req.SetBasicAuth(email, token)
	req.Header.Set("Accept", "application/json")

	resp, err := getHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()

	var ticket JiraTicket
	if err := json.NewDecoder(resp.Body).Decode(&ticket); err != nil {
		return nil
	}

	// Cache the result
	jiraCacheMu.Lock()
	jiraCache[ticketID] = &ticket
	jiraCacheMu.Unlock()

	return &ticket
}

// isActiveJiraStatus checks if a Jira status is considered "active"
func isActiveJiraStatus(status string) bool {
	activeStatuses := map[string]bool{
		"In Progress": true,
		"In Review":   true,
		"To Do":       true,
		"Pending":     true,
	}
	return activeStatuses[status]
}

// Jira ticket ID cache from JQL search
var (
	jiraJQLTicketIDs = make(map[string][]string) // map[JQL][]ticketID
	jiraJQLCacheMu   sync.RWMutex
	jiraJQLCacheTime time.Time
	jiraJQLCacheTTL  = 15 * time.Minute
)

// searchJiraByJQL searches for tickets using JQL and returns ticket IDs
// Results are cached for 15 minutes
func searchJiraByJQL(jql string) []string {
	if jql == "" {
		return nil // No JQL filter, return all tickets
	}

	// Check cache
	jiraJQLCacheMu.RLock()
	if cached, exists := jiraJQLTicketIDs[jql]; exists && time.Since(jiraJQLCacheTime) < jiraJQLCacheTTL {
		jiraJQLCacheMu.RUnlock()
		return cached
	}
	jiraJQLCacheMu.RUnlock()

	token, baseURL, email := getJiraConfig()
	if token == "" || baseURL == "" {
		return nil
	}

	// Build API URL for JQL search
	url := fmt.Sprintf("%s/rest/api/3/search/jql?jql=%s&fields=key&maxResults=1000",
		strings.TrimSuffix(baseURL, "/"),
		url.QueryEscape(jql))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	// Jira Cloud API requires Basic auth with email and API token
	req.SetBasicAuth(email, token)
	req.Header.Set("Accept", "application/json")

	resp, err := getHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}
	defer resp.Body.Close()

	var result struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}

	// Extract ticket IDs
	var ticketIDs []string
	for _, issue := range result.Issues {
		ticketIDs = append(ticketIDs, issue.Key)
	}

	// Cache the result
	jiraJQLCacheMu.Lock()
	jiraJQLTicketIDs[jql] = ticketIDs
	jiraJQLCacheTime = time.Now()
	jiraJQLCacheMu.Unlock()

	return ticketIDs
}

// isTicketInJQLResult checks if a ticket ID is in the JQL search results
func isTicketInJQLResult(ticketID string, jqlResults []string) bool {
	if jqlResults == nil || len(jqlResults) == 0 {
		return true // No JQL filter or empty result, all tickets are valid
	}
	for _, id := range jqlResults {
		if id == ticketID {
			return true
		}
	}
	return false
}

// findLocalRepos walks ~/projects/work looking for git repositories
func findLocalRepos(filter string, ch chan<- Repository) {
	// Load Jira config for JQL filtering
	jiraConfig, err := loadJiraConfig()
	if err != nil {
		jiraConfig = &JiraConfig{}
	}

	// Search for tickets using JQL (cached) - only if Jira is enabled
	var jqlTicketIDs []string
	if jiraConfig.Enabled && jiraConfig.JQL != "" {
		jqlTicketIDs = searchJiraByJQL(jiraConfig.JQL)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not get home directory: %v\n", err)
		return
	}

	workDir := filepath.Join(homeDir, "projects", "work")

	// Check if work directory exists
	if _, err := os.Stat(workDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "✗ Directory does not exist: %s\n", workDir)
		return
	}

	// Walk the directory tree
	err = filepath.Walk(workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip directories we can't access
			return nil
		}

		// Check if this is a .git directory
		if info.IsDir() && info.Name() == ".git" {
			repoPath := filepath.Dir(path)

			// Extract owner and name from path
			owner, name := extractRepoFromPath(repoPath, workDir)
			if owner == "" || name == "" {
				return filepath.SkipDir
			}

			// Get remote info
			url, platform := getRemoteInfo(repoPath)

			// Get description
			description := getRepoDescription(repoPath)

			// Check if repo has uncommitted changes
			isDirty := isRepoDirty(repoPath)

			// Check if repo has unpushed commits
			hasUnpushed := hasUnpushedCommits(repoPath)

			// Get current branch and all branches
			currentBranch := getCurrentBranch(repoPath)
			allBranches := getAllBranches(repoPath)

			var jiraTicketID, jiraStatus, jiraSummary string
			var hasActiveJiraTicket bool
			var jiraTicketIDs []string

			// Only scan branches for Jira tickets if integration is enabled
			if jiraConfig.Enabled {
				seenTickets := make(map[string]bool)

				for _, branch := range allBranches {
					ticketID := extractJiraTicketID(branch)
					if ticketID != "" && !seenTickets[ticketID] {
						if !isTicketInJQLResult(ticketID, jqlTicketIDs) {
							continue
						}
						seenTickets[ticketID] = true
						jiraTicketIDs = append(jiraTicketIDs, ticketID)
						if jiraTicketID == "" {
							jiraTicketID = ticketID
						}
					}
				}

				// Only fetch status for the primary ticket if we found one
				if jiraTicketID != "" {
					ticket := fetchJiraTicket(jiraTicketID)
					if ticket != nil {
						jiraStatus = ticket.Fields.Status.Name
						jiraSummary = ticket.Fields.Summary
						hasActiveJiraTicket = isActiveJiraStatus(jiraStatus)
					}
				}
			}

			// Create repository object
			repo := Repository{
				Platform:            platform,
				Owner:               owner,
				Name:                name,
				URL:                 url,
				Description:         description,
				LocalPath:           repoPath,
				IsDirty:             isDirty,
				HasUnpushed:         hasUnpushed,
				CurrentBranch:       currentBranch,
				JiraTicketID:        jiraTicketID,
				JiraTicketIDs:       jiraTicketIDs,
				JiraStatus:          jiraStatus,
				JiraSummary:         jiraSummary,
				HasActiveJiraTicket: hasActiveJiraTicket,
			}

			// Apply filter and send to channel
			if matchesFilter(&repo, filter) {
				ch <- repo
			}

			// Don't descend into the repository (skip .git subdirectories)
			return filepath.SkipDir
		}

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Error walking directory: %v\n", err)
	}
}

// browseLocalRepos finds local repositories and lets user select one
func browseLocalRepos(filter string, platform string) *Repository {
	repoChan := make(chan Repository, 100)

	go func() {
		fetchChan := make(chan Repository, 100)
		go func() {
			findLocalRepos(filter, fetchChan)
			close(fetchChan)
		}()

		// Filter by platform if specified
		for repo := range fetchChan {
			if platform == "" || repo.Platform == platform {
				repoChan <- repo
			}
		}
		close(repoChan)
	}()

	return selectRepoWithFzf(repoChan)
}

// ============================================================================
// Local Repository Operations
// ============================================================================

// executeCD outputs the repository path for the shell wrapper to cd into
func executeCD(repo *Repository) {
	fmt.Println(repo.LocalPath)
}

// executePull pulls the latest changes from the remote repository
func executePull(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Pulling latest changes for %s/%s...\n", repo.Owner, repo.Name)

	// Get current branch
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repo.LocalPath
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not get current branch: %v\n", err)
		os.Exit(1)
	}

	branch := strings.TrimSpace(string(output))

	// Pull from origin
	cmd = exec.Command("git", "pull", "origin", branch)
	cmd.Dir = repo.LocalPath
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to pull: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ Pulled latest changes\n")

	// Output path for cd
	fmt.Println(repo.LocalPath)
}

// executePush pushes commits to the remote repository
func executePush(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Pushing commits for %s/%s...\n", repo.Owner, repo.Name)

	// Get current branch
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repo.LocalPath
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not get current branch: %v\n", err)
		os.Exit(1)
	}

	branch := strings.TrimSpace(string(output))

	// Push to origin
	cmd = exec.Command("git", "push", "origin", branch)
	cmd.Dir = repo.LocalPath
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to push: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ Pushed commits to origin/%s\n", branch)

	// Output path for cd
	fmt.Println(repo.LocalPath)
}

// executeEdit signals to the shell wrapper to open the editor
func executeEdit(repo *Repository) {
	// Output special prefix so shell wrapper knows to open editor
	fmt.Printf("EDIT:%s\n", repo.LocalPath)
}

// executeCheckout lets user select and checkout a different branch
func executeCheckout(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Fetching branches for %s/%s...\n", repo.Owner, repo.Name)

	// Get all branches (local and remote)
	cmd := exec.Command("git", "branch", "-a", "--format=%(refname:short)")
	cmd.Dir = repo.LocalPath
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not get branches: %v\n", err)
		os.Exit(1)
	}

	branches := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(branches) == 0 {
		fmt.Fprintf(os.Stderr, "✗ No branches found\n")
		os.Exit(1)
	}

	// Get current branch
	cmd = exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repo.LocalPath
	output, err = cmd.Output()
	currentBranch := strings.TrimSpace(string(output))

	// Deduplicate branches (remove remote duplicates)
	seen := make(map[string]bool)
	var uniqueBranches []string
	for _, branch := range branches {
		branch = strings.TrimSpace(branch)
		if branch == "" || branch == "HEAD" {
			continue
		}
		// Strip origin/ prefix for deduplication
		displayBranch := strings.TrimPrefix(branch, "origin/")
		if !seen[displayBranch] {
			seen[displayBranch] = true
			uniqueBranches = append(uniqueBranches, displayBranch)
		}
	}

	// Show branches in fzf
	fzfCmd := exec.Command("fzf",
		"--ansi",
		"--height=40%",
		"--reverse",
		"--header=Select branch to checkout | Ctrl-C to cancel")

	stdin, err := fzfCmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not create stdin pipe: %v\n", err)
		os.Exit(1)
	}

	stdout, err := fzfCmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not create stdout pipe: %v\n", err)
		os.Exit(1)
	}

	fzfCmd.Stderr = os.Stderr

	if err := fzfCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not start fzf: %v\n", err)
		os.Exit(1)
	}

	// Write branches to fzf, highlighting current branch
	for _, branch := range uniqueBranches {
		if branch == currentBranch {
			stdin.Write([]byte(fmt.Sprintf("\033[32m* %s\033[0m\n", branch)))
		} else {
			stdin.Write([]byte(branch + "\n"))
		}
	}
	stdin.Close()

	output, err = io.ReadAll(stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not read fzf output: %v\n", err)
		os.Exit(1)
	}

	if err := fzfCmd.Wait(); err != nil {
		// User cancelled
		os.Exit(0)
	}

	selectedBranch := strings.TrimSpace(string(output))
	// Remove color codes and asterisk if present
	selectedBranch = strings.TrimPrefix(selectedBranch, "* ")

	if selectedBranch == "" {
		os.Exit(0)
	}

	// Checkout the branch
	fmt.Fprintf(os.Stderr, "Checking out %s...\n", selectedBranch)
	cmd = exec.Command("git", "checkout", selectedBranch)
	cmd.Dir = repo.LocalPath
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to checkout branch: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ Checked out %s\n", selectedBranch)

	// Output path for cd
	fmt.Println(repo.LocalPath)
}

// executeDelete deletes a repository after confirmation
func executeDelete(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Delete %s/%s?\n", repo.Owner, repo.Name)
	fmt.Fprintf(os.Stderr, "Path: %s\n\n", repo.LocalPath)

	// Show confirmation with fzf
	cmd := exec.Command("fzf",
		"--ansi",
		"--height=5",
		"--reverse",
		"--header=Confirm deletion (select yes to delete)")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not create stdin pipe: %v\n", err)
		os.Exit(1)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not create stdout pipe: %v\n", err)
		os.Exit(1)
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not start fzf: %v\n", err)
		os.Exit(1)
	}

	// Offer yes/no options
	stdin.Write([]byte("yes\nno\n"))
	stdin.Close()

	output, err := io.ReadAll(stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not read fzf output: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Wait(); err != nil {
		// User cancelled
		os.Exit(0)
	}

	choice := strings.TrimSpace(string(output))
	if choice != "yes" {
		os.Exit(0)
	}

	// Delete the repository
	fmt.Fprintf(os.Stderr, "Deleting %s...\n", repo.LocalPath)
	if err := os.RemoveAll(repo.LocalPath); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to delete repository: %v\n", err)
		os.Exit(1)
	}

	// Clean up empty parent directories
	cleanupEmptyDirs(repo.LocalPath)

	fmt.Fprintf(os.Stderr, "✓ Deleted %s/%s\n", repo.Owner, repo.Name)
	os.Exit(0)
}

// cleanupEmptyDirs removes empty parent directories up to ~/projects/work
func cleanupEmptyDirs(repoPath string) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return
	}

	workDir := filepath.Join(homeDir, "projects", "work")
	currentDir := filepath.Dir(repoPath)

	for currentDir != workDir && strings.HasPrefix(currentDir, workDir) {
		// Try to remove the directory (will only succeed if empty)
		if err := os.Remove(currentDir); err != nil {
			// Directory not empty or error, stop cleanup
			break
		}
		currentDir = filepath.Dir(currentDir)
	}
}

// executeJiraOpen opens the Jira ticket in the default browser
func executeJiraOpen(repo *Repository) {
	_, baseURL, _ := getJiraConfig()
	if baseURL == "" || repo.JiraTicketID == "" {
		fmt.Fprintf(os.Stderr, "✗ Jira configuration or ticket ID not found\n")
		os.Exit(1)
	}

	// Build ticket URL: https://example.atlassian.net/browse/PROJ-123
	url := fmt.Sprintf("%s/browse/%s",
		strings.TrimSuffix(baseURL, "/"), repo.JiraTicketID)

	// Open in browser (cross-platform)
	var cmd *exec.Cmd
	switch {
	case strings.Contains(strings.ToLower(os.Getenv("OSTYPE")), "darwin"):
		cmd = exec.Command("open", url)
	case strings.Contains(strings.ToLower(os.Getenv("OSTYPE")), "linux"):
		cmd = exec.Command("xdg-open", url)
	default:
		cmd = exec.Command("cmd", "/c", "start", url)
	}

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to open browser: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ Opening %s in browser...\n", url)

	// Still output path for cd
	fmt.Println(repo.LocalPath)
}

// executeJiraStatus displays detailed Jira ticket information
func executeJiraStatus(repo *Repository) {
	if repo.JiraTicketID == "" {
		fmt.Fprintf(os.Stderr, "✗ No Jira ticket associated with this repository\n")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\n\033[1mJira Ticket Details\033[0m\n")
	fmt.Fprintf(os.Stderr, "─────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "Ticket ID:    %s\n", repo.JiraTicketID)
	fmt.Fprintf(os.Stderr, "Status:       %s\n", repo.JiraStatus)
	fmt.Fprintf(os.Stderr, "Summary:      %s\n", repo.JiraSummary)
	fmt.Fprintf(os.Stderr, "Branch:       %s\n", repo.CurrentBranch)
	fmt.Fprintf(os.Stderr, "Repository:   %s/%s\n", repo.Owner, repo.Name)
	fmt.Fprintf(os.Stderr, "Path:         %s\n", repo.LocalPath)
	fmt.Fprintf(os.Stderr, "─────────────────────────────────\n\n")

	// Output path for cd
	fmt.Println(repo.LocalPath)
}

// performLocalOperation shows an operation menu and executes the selected operation
func performLocalOperation(repo *Repository) {
	operations := []string{
		"cd       Navigate to repository",
		"pull     Pull latest changes",
		"push     Push commits to remote",
		"checkout Checkout a different branch",
		"delete   Delete repository",
		"edit     Open in $EDITOR",
	}

	// Add Jira operations if ticket info is available
	if repo.JiraTicketID != "" && repo.JiraStatus != "" {
		jiraOps := []string{
			"jira-open   Open Jira ticket in browser",
			"jira-status Show Jira ticket details",
		}
		operations = append(jiraOps, operations...)
	}

	// Create preview showing repo info and recent commits
	previewText := fmt.Sprintf("%s/%s\nPath: %s\n\nRecent commits:\n", repo.Owner, repo.Name, repo.LocalPath)

	cmd := exec.Command("fzf",
		"--ansi",
		"--height=50%",
		"--reverse",
		"--header=Select operation | Ctrl-C to cancel",
		"--preview", fmt.Sprintf("echo '%s' && git -C '%s' log --oneline -10 2>/dev/null || echo 'No commits'", previewText, repo.LocalPath),
		"--preview-window=right:50%")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not create stdin pipe: %v\n", err)
		os.Exit(1)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not create stdout pipe: %v\n", err)
		os.Exit(1)
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not start fzf: %v\n", err)
		os.Exit(1)
	}

	// Write operations to fzf
	for _, op := range operations {
		stdin.Write([]byte(op + "\n"))
	}
	stdin.Close()

	output, err := io.ReadAll(stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not read fzf output: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Wait(); err != nil {
		// User cancelled
		os.Exit(0)
	}

	selectedLine := strings.TrimSpace(string(output))
	operation := strings.Fields(selectedLine)[0]

	// Execute the selected operation
	switch operation {
	case "cd":
		executeCD(repo)
	case "pull":
		executePull(repo)
	case "push":
		executePush(repo)
	case "checkout":
		executeCheckout(repo)
	case "delete":
		executeDelete(repo)
	case "edit":
		executeEdit(repo)
	case "jira-open":
		executeJiraOpen(repo)
	case "jira-status":
		executeJiraStatus(repo)
	default:
		os.Exit(0)
	}
}

func main() {
	// Parse command line arguments
	args := parseArgs()

	// Check dependencies (fzf, git)
	for _, cmd := range []string{"fzf", "git"} {
		if _, err := exec.LookPath(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "✗ Missing %s. Install with: brew install %s\n", cmd, cmd)
			os.Exit(1)
		}
	}

	// Handle local-only mode
	if args.LocalMode {
		selectedRepo := browseLocalRepos(args.Filter, args.Platform)
		if selectedRepo == nil {
			os.Exit(0)
		}

		performLocalOperation(selectedRepo)
		return
	}

	// Load config for exclude patterns
	config, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load config: %v\n", err)
		config = &Config{ExcludePatterns: []string{}}
	}

	// Fetch repositories based on mode
	// Create channel for collecting repos
	fetchChan := make(chan Repository, 500)
	var wg sync.WaitGroup
	var cacheWg sync.WaitGroup // Track cache save goroutines

	// Determine what to fetch
	fetchRemote := !args.LocalMode
	fetchLocal := !args.RemoteOnly

	// Determine which platforms to fetch from
	shouldFetchGitHub := fetchRemote && (args.Platform == "" || args.Platform == "github")
	shouldFetchGitLab := fetchRemote && (args.Platform == "" || args.Platform == "gitlab")

	// Fetch local repos FIRST (blocking) so they appear before remote repos
	if fetchLocal {
		findLocalRepos(args.Filter, fetchChan)
	}

	// Then fetch remote repos in background
	if shouldFetchGitHub {
		wg.Add(1)

		// If filter provided, use search API for speed
		if args.Filter != "" {
			go func() {
				defer wg.Done()
				searchGitHub(args.Filter, fetchChan)
			}()
		} else {
			go func() {
				defer wg.Done()
				fetchGitHub(fetchChan, args.NoCache, true, &cacheWg)
			}()
		}
	}

	if shouldFetchGitLab {
		wg.Add(1)

		// If filter provided, use search API for speed
		if args.Filter != "" {
			go func() {
				defer wg.Done()
				searchGitLab(args.Filter, fetchChan)
			}()
		} else {
			go func() {
				defer wg.Done()
				fetchGitLab(fetchChan, args.NoCache, true, &cacheWg)
			}()
		}
	}

	// Deduplicate and stream to fzf in real-time
	repoChan := make(chan Repository, 500)

	go func() {
		defer close(repoChan)

		seen := make(map[string]*Repository) // key: "owner/name", value: pointer to sent repo
		var mu sync.Mutex

		for repo := range fetchChan {
			// Filter by platform if specified
			if args.Platform != "" && repo.Platform != args.Platform {
				continue
			}

			// Filter by Jira ticket if --jira flag is set
			if args.JiraFilter {
				// Only show repos with active Jira tickets
				if !repo.HasActiveJiraTicket {
					continue
				}
			}

			// Filter by config exclude patterns
			if shouldExcludeRepo(repo, config) {
				continue
			}

			key := repo.Owner + "/" + repo.Name

			mu.Lock()
			existing, exists := seen[key]

			if !exists {
				// First time seeing this repo - send it
				seen[key] = &repo
				mu.Unlock()
				repoChan <- repo
			} else {
				// Already seen - check if this version is better (local > remote)
				if repo.LocalPath != "" && existing.LocalPath == "" {
					// This is local, existing was remote - replace it
					// We can't unsend the old one, but local will be visible later in the list
					seen[key] = &repo
					mu.Unlock()
					repoChan <- repo
				} else {
					// Keep existing (either both local, both remote, or existing is local)
					mu.Unlock()
				}
			}
		}
	}()

	// Close fetchChan when all fetching is done
	go func() {
		wg.Wait()
		close(fetchChan)
	}()

	// Let user select repository with fzf (streams in real-time)
	selectedRepo := selectRepoWithFzf(repoChan)
	if selectedRepo == nil {
		cacheWg.Wait() // Ensure cache saves complete before exit
		os.Exit(0)
	}

	// If user selected a local repo, show operation menu instead of cloning
	if selectedRepo.LocalPath != "" {
		performLocalOperation(selectedRepo)
		return
	}

	// Get default branch and let user select branch
	defaultBranch := getDefaultBranch(selectedRepo)
	selectedBranch := selectBranchWithFzf(selectedRepo, defaultBranch)

	// Clone or update the repository
	targetDir := cloneOrUpdate(selectedRepo, selectedBranch)

	// Ensure cache saves complete before exit
	cacheWg.Wait()

	// Output directory for shell wrapper to cd into
	fmt.Println(targetDir)
}

// ============================================================================
// GitHub API Operations
// ============================================================================

// fetchGitHubAllPages fetches all pages from GitHub API and returns repos
func fetchGitHubAllPages(token string) []Repository {
	var allRepos []Repository

	// Fetch first 3 pages in parallel
	type pageResult struct {
		page  int
		repos []Repository
	}

	resultChan := make(chan pageResult, 3)

	for p := 1; p <= 3; p++ {
		page := p
		go func() {
			repos := fetchGitHubPage(page, token)
			resultChan <- pageResult{page: page, repos: repos}
		}()
	}

	// Collect first 3 pages
	results := make(map[int][]Repository)
	for i := 0; i < 3; i++ {
		result := <-resultChan
		results[result.page] = result.repos
	}

	// Accumulate repos
	for page := 1; page <= 3; page++ {
		allRepos = append(allRepos, results[page]...)
		if len(results[page]) < 100 {
			return allRepos
		}
	}

	// Continue sequential for remaining pages
	for page := 4; ; page++ {
		repos := fetchGitHubPage(page, token)
		allRepos = append(allRepos, repos...)
		if len(repos) < 100 {
			break
		}
	}

	return allRepos
}

func fetchGitHub(ch chan<- Repository, noCache bool, backgroundRefresh bool, cacheWg *sync.WaitGroup) {
	token := getGitHubToken()
	if token == "" {
		return
	}

	// Try to load from cache first (unless --no-cache)
	var cachedRepos []Repository

	if !noCache {
		cachedRepos = loadReposFromDB("github")
	}

	// If cache exists, serve it immediately
	if len(cachedRepos) > 0 {
		for _, repo := range cachedRepos {
			ch <- repo
		}

		// Background refresh if cache is stale
		if backgroundRefresh && isBatchStale("github") {
			cacheWg.Add(1)
			go func() {
				defer cacheWg.Done()
				freshRepos := fetchGitHubAllPages(token)
				if len(freshRepos) > 0 {
					if err := saveReposToDB("github", freshRepos); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to save cache: %v\n", err)
					}
				}
			}()
		}
		return
	}

	// Cache is missing or bypassed - fetch from API
	freshRepos := fetchGitHubAllPages(token)

	// Stream to channel
	for _, repo := range freshRepos {
		ch <- repo
	}

	// Save to cache synchronously
	if len(freshRepos) > 0 {
		if err := saveReposToDB("github", freshRepos); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save cache: %v\n", err)
		}
	}
}

func fetchGitHubPage(page int, token string) []Repository {
	url := fmt.Sprintf("https://api.github.com/user/repos?per_page=100&page=%d&affiliation=owner,collaborator,organization_member", page)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := getHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}

	var repos []struct {
		Name        string                 `json:"name"`
		Owner       struct{ Login string } `json:"owner"`
		Description *string                `json:"description"`
		SSHURL      string                 `json:"ssh_url"`
		Language    *struct{ Name string } `json:"language"`
		Stars       int                    `json:"stargazers_count"`
	}

	json.NewDecoder(resp.Body).Decode(&repos)
	resp.Body.Close()

	var result []Repository
	for _, r := range repos {
		desc := "No description"
		if r.Description != nil {
			desc = *r.Description
		}
		lang := "Unknown"
		if r.Language != nil {
			lang = r.Language.Name
		}

		result = append(result, Repository{
			Platform:    "github",
			Owner:       r.Owner.Login,
			Name:        r.Name,
			URL:         r.SSHURL,
			Language:    lang,
			Stars:       r.Stars,
			Description: desc,
		})
	}

	return result
}

func searchGitHub(query string, ch chan<- Repository) {
	token := getGitHubToken()
	if token == "" {
		return
	}

	// Fetch first 3 pages in parallel for speed
	type pageResult struct {
		page  int
		repos []Repository
	}

	resultChan := make(chan pageResult, 3)

	for p := 1; p <= 3; p++ {
		page := p
		go func() {
			repos := searchGitHubPage(query, page, token)
			resultChan <- pageResult{page: page, repos: repos}
		}()
	}

	// Collect first 3 pages
	results := make(map[int][]Repository)
	for i := 0; i < 3; i++ {
		result := <-resultChan
		results[result.page] = result.repos
	}

	// Stream pages in order
	for page := 1; page <= 3; page++ {
		for _, repo := range results[page] {
			ch <- repo
		}
		if len(results[page]) < 100 {
			return // No more pages
		}
	}

	// Continue sequential for remaining pages (rare case)
	for page := 4; ; page++ {
		repos := searchGitHubPage(query, page, token)
		for _, repo := range repos {
			ch <- repo
		}
		if len(repos) < 100 {
			break
		}
	}
}

func searchGitHubPage(query string, page int, token string) []Repository {
	url := fmt.Sprintf("https://api.github.com/search/repositories?q=%s+user:@me&per_page=100&page=%d", query, page)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := getHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}

	var result struct {
		Items []struct {
			Name        string                 `json:"name"`
			Owner       struct{ Login string } `json:"owner"`
			Description *string                `json:"description"`
			SSHURL      string                 `json:"ssh_url"`
			Language    *string                `json:"language"`
			Stars       int                    `json:"stargazers_count"`
		} `json:"items"`
	}

	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()

	var repos []Repository
	for _, r := range result.Items {
		desc := "No description"
		if r.Description != nil {
			desc = *r.Description
		}
		lang := "Unknown"
		if r.Language != nil {
			lang = *r.Language
		}

		repos = append(repos, Repository{
			Platform:    "github",
			Owner:       r.Owner.Login,
			Name:        r.Name,
			URL:         r.SSHURL,
			Language:    lang,
			Stars:       r.Stars,
			Description: desc,
		})
	}

	return repos
}

// ============================================================================
// GitLab API Operations
// ============================================================================

// fetchGitLabAllPages fetches all pages from GitLab API and returns repos
func fetchGitLabAllPages(token string) []Repository {
	var allRepos []Repository

	// Fetch first 3 pages in parallel
	type pageResult struct {
		page  int
		repos []Repository
	}

	resultChan := make(chan pageResult, 3)

	for p := 1; p <= 3; p++ {
		page := p
		go func() {
			repos := fetchGitLabPage(page, token)
			resultChan <- pageResult{page: page, repos: repos}
		}()
	}

	// Collect first 3 pages
	results := make(map[int][]Repository)
	for i := 0; i < 3; i++ {
		result := <-resultChan
		results[result.page] = result.repos
	}

	// Accumulate repos
	for page := 1; page <= 3; page++ {
		allRepos = append(allRepos, results[page]...)
		if len(results[page]) < 100 {
			return allRepos
		}
	}

	// Continue sequential for remaining pages
	for page := 4; ; page++ {
		repos := fetchGitLabPage(page, token)
		allRepos = append(allRepos, repos...)
		if len(repos) < 100 {
			break
		}
	}

	return allRepos
}

func fetchGitLab(ch chan<- Repository, noCache bool, backgroundRefresh bool, cacheWg *sync.WaitGroup) {
	token := getGitLabToken()
	if token == "" {
		return
	}

	// Try to load from cache first (unless --no-cache)
	var cachedRepos []Repository

	if !noCache {
		cachedRepos = loadReposFromDB("gitlab")
	}

	// If cache exists, serve it immediately
	if len(cachedRepos) > 0 {
		for _, repo := range cachedRepos {
			ch <- repo
		}

		// Background refresh if cache is stale (don't block exit)
		if backgroundRefresh && isBatchStale("gitlab") {
			cacheWg.Add(1)
			go func() {
				defer cacheWg.Done()
				freshRepos := fetchGitLabAllPages(token)
				if len(freshRepos) > 0 {
					if err := saveReposToDB("gitlab", freshRepos); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to save cache: %v\n", err)
					}
				}
			}()
		}
		return
	}

	// Cache is missing or bypassed - fetch from API
	freshRepos := fetchGitLabAllPages(token)

	// Stream to channel
	for _, repo := range freshRepos {
		ch <- repo
	}

	// Save to cache synchronously
	if len(freshRepos) > 0 {
		if err := saveReposToDB("gitlab", freshRepos); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save cache: %v\n", err)
		}
	}
}

func fetchGitLabPage(page int, token string) []Repository {
	url := fmt.Sprintf("https://gitlab.com/api/v4/projects?membership=true&archived=false&per_page=100&page=%d", page)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := getHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}

	var repos []struct {
		Name              string  `json:"name"`
		PathWithNamespace string  `json:"path_with_namespace"`
		Description       *string `json:"description"`
		SSHURL            string  `json:"ssh_url_to_repo"`
		Stars             int     `json:"star_count"`
	}

	json.NewDecoder(resp.Body).Decode(&repos)
	resp.Body.Close()

	var result []Repository
	for _, r := range repos {
		desc := "No description"
		if r.Description != nil {
			desc = *r.Description
		}

		// Split path_with_namespace to get owner and repo name
		// e.g., "ops/terraform/gcp/syncserver/syncserver" -> owner="ops/terraform/gcp/syncserver", name="syncserver"
		parts := strings.Split(r.PathWithNamespace, "/")
		repoName := parts[len(parts)-1]
		ownerPath := strings.Join(parts[:len(parts)-1], "/")

		result = append(result, Repository{
			Platform:    "gitlab",
			Owner:       ownerPath,
			Name:        repoName,
			URL:         r.SSHURL,
			Language:    "Unknown",
			Stars:       r.Stars,
			Description: desc,
		})
	}

	return result
}

func searchGitLab(query string, ch chan<- Repository) {
	token := getGitLabToken()
	if token == "" {
		return
	}

	// Fetch first 3 pages in parallel for speed
	type pageResult struct {
		page  int
		repos []Repository
	}

	resultChan := make(chan pageResult, 3)

	for p := 1; p <= 3; p++ {
		page := p
		go func() {
			repos := searchGitLabPage(query, page, token)
			resultChan <- pageResult{page: page, repos: repos}
		}()
	}

	// Collect first 3 pages
	results := make(map[int][]Repository)
	for i := 0; i < 3; i++ {
		result := <-resultChan
		results[result.page] = result.repos
	}

	// Stream pages in order
	for page := 1; page <= 3; page++ {
		for _, repo := range results[page] {
			ch <- repo
		}
		if len(results[page]) < 100 {
			return // No more pages
		}
	}

	// Continue sequential for remaining pages (rare case)
	for page := 4; ; page++ {
		repos := searchGitLabPage(query, page, token)
		for _, repo := range repos {
			ch <- repo
		}
		if len(repos) < 100 {
			break
		}
	}
}

func searchGitLabPage(query string, page int, token string) []Repository {
	url := fmt.Sprintf("https://gitlab.com/api/v4/projects?membership=true&archived=false&search=%s&per_page=100&page=%d", query, page)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := getHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return nil
	}

	var repos []struct {
		Name              string  `json:"name"`
		PathWithNamespace string  `json:"path_with_namespace"`
		Description       *string `json:"description"`
		SSHURL            string  `json:"ssh_url_to_repo"`
		Stars             int     `json:"star_count"`
	}

	json.NewDecoder(resp.Body).Decode(&repos)
	resp.Body.Close()

	var result []Repository
	for _, r := range repos {
		desc := "No description"
		if r.Description != nil {
			desc = *r.Description
		}

		// Split path_with_namespace to get owner and repo name
		// e.g., "ops/terraform/gcp/syncserver/syncserver" -> owner="ops/terraform/gcp/syncserver", name="syncserver"
		parts := strings.Split(r.PathWithNamespace, "/")
		repoName := parts[len(parts)-1]
		ownerPath := strings.Join(parts[:len(parts)-1], "/")

		result = append(result, Repository{
			Platform:    "gitlab",
			Owner:       ownerPath,
			Name:        repoName,
			URL:         r.SSHURL,
			Language:    "Unknown",
			Stars:       r.Stars,
			Description: desc,
		})
	}

	return result
}

// ============================================================================
// Repository Selection with fzf
// ============================================================================

func selectRepoWithFzf(repoChan <-chan Repository) *Repository {
	// Start fzf immediately with preview
	// Format in stdin: [GitHub] owner/name\tstars\tlanguage\tdescription\tplatform
	// or [Local: GitHub] owner/name\tstars\tlanguage\tdescription\tplatform
	// Preview shows: repo name, description, and platform icon
	previewCmd := `echo {} | awk -F'\t' '{
		name = $1
		gsub(/\x1b\[[0-9;]*m/, "", name)
		desc = $4
		platform = $5
		icon = (platform == "github") ? " " : " "
		print name
		print ""
		print desc
		print ""
		print icon
	}'`

	cmd := exec.Command("fzf",
		"--ansi",
		"--height=80%",
		"--reverse",
		"--header=Select repository | Ctrl-C to cancel",
		"--preview", previewCmd,
		"--preview-window=up:4:wrap",
		"--delimiter=\t",
		"--with-nth=1")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}

	cmd.Stderr = os.Stderr

	// Start fzf
	if err := cmd.Start(); err != nil {
		return nil
	}

	// Stream repos to fzf as they arrive and store them for later matching
	var repos []Repository
	var mu sync.Mutex

	go func() {
		defer stdin.Close()
		for repo := range repoChan {
			mu.Lock()
			repos = append(repos, repo)
			mu.Unlock()

			// Determine platform tag and color
			var platformTag, color string
			if repo.LocalPath != "" {
				// This is a local repo - show platform based on detected remote
				if repo.Platform == "github" {
					platformTag, color = "[Local: GitHub]", "\033[32m"
				} else if repo.Platform == "gitlab" {
					platformTag, color = "[Local: GitLab]", "\033[32m"
				} else {
					platformTag, color = "[Local]", "\033[32m"
				}
			} else {
				// This is a remote repo from API
				if repo.Platform == "gitlab" {
					platformTag, color = "[GitLab]", "\033[33m"
				} else {
					platformTag, color = "[GitHub]", "\033[34m"
				}
			}

			// Add status indicators for local repos
			repoName := repo.Owner + "/" + repo.Name
			if repo.IsDirty {
				repoName = repoName + " \033[31m*\033[0m" // Red asterisk for uncommitted changes
			}
			if repo.HasUnpushed {
				repoName = repoName + " \033[33m^\033[0m" // Yellow caret for unpushed commits
			}

			// Add Jira ticket indicator (for local repos only)
			if repo.LocalPath != "" && len(repo.JiraTicketIDs) > 0 {
				// Format ticket IDs as comma-separated list
				ticketsList := strings.Join(repo.JiraTicketIDs, ", ")

				if repo.JiraStatus != "" {
					// Color code by status
					var statusColor string
					switch {
					case isActiveJiraStatus(repo.JiraStatus):
						statusColor = "\033[32m" // Green for active
					case repo.JiraStatus == "Done" || repo.JiraStatus == "Closed":
						statusColor = "\033[90m" // Gray for done
					default:
						statusColor = "\033[36m" // Cyan for other
					}
					repoName = repoName + fmt.Sprintf(" %s[%s: %s]\033[0m",
						statusColor, ticketsList, repo.JiraStatus)
				} else {
					// API failed - just show ticket IDs
					repoName = repoName + fmt.Sprintf(" \033[35m[%s]\033[0m", ticketsList)
				}
			}

			// Format: [GitHub] owner/name\tstars\tlanguage\tdescription\tplatform
			// or [Local: GitHub] owner/name * ^\tstars\tlanguage\tdescription\tplatform
			// Tab delimiter allows us to extract details in preview
			line := fmt.Sprintf("%s%s\033[0m %s\t%d\t%s\t%s\t%s\n",
				color, platformTag, repoName,
				repo.Stars, repo.Language, repo.Description, repo.Platform)
			stdin.Write([]byte(line))
		}
	}()

	// Read fzf output
	output, err := io.ReadAll(stdout)
	if err != nil {
		return nil
	}

	// Wait for fzf to complete
	if err := cmd.Wait(); err != nil {
		return nil
	}

	selectedLine := strings.TrimSpace(string(output))

	// Extract owner/name from the selected line
	// Format: "[GitHub] owner/name\tstars\tlanguage\tdescription"
	// or "[Local: GitHub] owner/name [DEVOPS-1094]\tstars\tlanguage\tdescription"
	// First split by tab to get just the display part
	mainPart := strings.Split(selectedLine, "\t")[0]

	// Strip Jira ticket indicator if present (e.g., "[DEVOPS-1094]" or "[DEVOPS-1094: In Progress]" or "[COR-8604, ISD-8604]")
	jiraRegex := regexp.MustCompile(` \[([^\]]+)\]`)
	mainPart = jiraRegex.ReplaceAllString(mainPart, "")

	// Strip status indicators (* for dirty, ^ for unpushed)
	mainPart = strings.ReplaceAll(mainPart, " *", "")
	mainPart = strings.ReplaceAll(mainPart, " ^", "")

	// Then extract owner/name - it's the last field after the platform tag
	parts := strings.Fields(mainPart)
	if len(parts) < 2 {
		return nil
	}

	// The owner/name is typically parts[1] or parts[2] depending on format
	// Format: "[Local: GitHub] owner/name" -> parts[0]="[Local:", parts[1]="GitHub]", parts[2]="owner/name"
	// Or: "[GitHub] owner/name" -> parts[0]="[GitHub]", parts[1]="owner/name"
	ownerName := parts[1]
	if len(parts) >= 3 && strings.HasSuffix(parts[1], "]") {
		// parts[1] ends with "]", so it's part of the platform tag
		// owner/name is in parts[2]
		ownerName = parts[2]
	}

	// Find matching repo - it must be in our slice already since fzf showed it
	mu.Lock()
	defer mu.Unlock()
	for i := range repos {
		repoFullName := repos[i].Owner + "/" + repos[i].Name
		if repoFullName == ownerName {
			return &repos[i]
		}
	}

	return nil
}

// ============================================================================
// Branch Operations
// ============================================================================

func getDefaultBranch(repo *Repository) string {
	var token, url string

	if repo.Platform == "github" {
		token = getGitHubToken()
		url = fmt.Sprintf("https://api.github.com/repos/%s/%s", repo.Owner, repo.Name)
	} else {
		token = getGitLabToken()
		projectPath := strings.ReplaceAll(repo.Owner+"/"+repo.Name, "/", "%2F")
		url = fmt.Sprintf("https://gitlab.com/api/v4/projects/%s", projectPath)
	}

	if token == "" {
		return "main"
	}

	req, _ := http.NewRequest("GET", url, nil)
	if repo.Platform == "github" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
	} else {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	resp, err := getHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return "main"
	}
	defer resp.Body.Close()

	var result struct {
		DefaultBranch string `json:"default_branch"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if result.DefaultBranch == "" {
		return "main"
	}
	return result.DefaultBranch
}

func selectBranchWithFzf(repo *Repository, defaultBranch string) string {

	// Fetch branches
	var token, url string

	if repo.Platform == "github" {
		token = getGitHubToken()
		url = fmt.Sprintf("https://api.github.com/repos/%s/%s/branches", repo.Owner, repo.Name)
	} else {
		token = getGitLabToken()
		projectPath := strings.ReplaceAll(repo.Owner+"/"+repo.Name, "/", "%2F")
		url = fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/repository/branches", projectPath)
	}

	if token == "" {
		return defaultBranch
	}

	req, _ := http.NewRequest("GET", url, nil)
	if repo.Platform == "github" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
	} else {
		req.Header.Set("PRIVATE-TOKEN", token)
	}

	resp, err := getHTTPClient().Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return defaultBranch
	}
	defer resp.Body.Close()

	var branches []struct {
		Name string `json:"name"`
	}
	json.NewDecoder(resp.Body).Decode(&branches)

	if len(branches) == 0 {
		return defaultBranch
	}

	// Build branch list
	var branchNames []string
	for _, b := range branches {
		branchNames = append(branchNames, b.Name)
	}

	// Sort branches: main/master first if they exist
	var sortedBranches []string
	var hasMain, hasMaster bool
	var otherBranches []string

	for _, name := range branchNames {
		if name == "main" {
			hasMain = true
		} else if name == "master" {
			hasMaster = true
		} else {
			otherBranches = append(otherBranches, name)
		}
	}

	if hasMain {
		sortedBranches = append(sortedBranches, "main")
	}
	if hasMaster {
		sortedBranches = append(sortedBranches, "master")
	}
	sortedBranches = append(sortedBranches, otherBranches...)
	branchNames = sortedBranches

	// If only one branch, return it directly without fzf
	if len(branchNames) == 1 {
		return branchNames[0]
	}

	// Run fzf for branch selection
	cmd := exec.Command("fzf",
		"--ansi",
		"--height=40%",
		"--reverse",
		fmt.Sprintf("--header=Select branch (default: %s)", defaultBranch))

	cmd.Stdin = strings.NewReader(strings.Join(branchNames, "\n"))
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		return defaultBranch
	}

	selected := strings.TrimSpace(string(output))
	if selected == "" {
		return defaultBranch
	}
	return selected
}

// ============================================================================
// Clone or Update Repository
// ============================================================================

func cloneOrUpdate(repo *Repository, branch string) string {
	homeDir, _ := os.UserHomeDir()
	targetDir := filepath.Join(homeDir, "projects", "work", repo.Owner, repo.Name)

	// If directory exists, checkout branch and pull
	if _, err := os.Stat(targetDir); err == nil {
		if _, err := os.Stat(filepath.Join(targetDir, ".git")); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "✗ Directory exists but is not a git repository")
			os.Exit(1)
		}

		// Get current branch
		cmd := exec.Command("git", "branch", "--show-current")
		cmd.Dir = targetDir
		output, _ := cmd.Output()
		currentBranch := strings.TrimSpace(string(output))

		// Checkout branch if different
		if currentBranch != branch {
			// Try to checkout existing local branch first
			checkoutCmd := exec.Command("git", "checkout", branch)
			checkoutCmd.Dir = targetDir
			checkoutCmd.Stdout = nil
			checkoutCmd.Stderr = nil

			// If that fails, checkout as tracking branch from remote
			if err := checkoutCmd.Run(); err != nil {
				trackCmd := exec.Command("git", "checkout", "-t", "origin/"+branch)
				trackCmd.Dir = targetDir
				trackCmd.Stdout = nil
				trackCmd.Stderr = os.Stderr
				trackCmd.Run()
			}
		}

		// Pull latest
		cmd = exec.Command("git", "pull")
		cmd.Dir = targetDir
		cmd.Stdout = nil
		cmd.Stderr = os.Stderr
		cmd.Run()

		return targetDir
	}

	// Clone new repository with specific branch
	os.MkdirAll(filepath.Dir(targetDir), 0755)

	cmd := exec.Command("git", "clone", "-b", branch, repo.URL, targetDir)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to clone: %v\n", err)
		os.Exit(1)
	}

	return targetDir
}
