package main

type Repository struct {
	Platform    string
	Owner       string
	Name        string
	URL         string // SSH clone URL (kept for backwards-compat with cached records)
	HTTPSURL    string // HTTPS clone URL (used when Settings.CloneProtocol == "https")
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

// Settings holds platform-level user configuration loaded from clones.yml + env vars.
type Settings struct {
	GitHubHost    string // default "github.com" — supports GitHub Enterprise Server
	GitLabHost    string // default "gitlab.com" — supports self-hosted instances
	CloneProtocol string // "ssh" (default) or "https"
}

// JiraConfig holds user configuration for Jira integration
type JiraConfig struct {
	Enabled        bool     // Whether Jira integration is enabled (default: false)
	Token          string   // API token (can also use JIRA_API_TOKEN env var)
	BaseURL        string   // Base URL (can also use JIRA_BASE_URL env var)
	Email          string   // User email for currentUser() resolution (optional)
	JQL            string   // JQL query to filter tickets
	ActiveStatuses []string // Custom list of active statuses (if not set, uses defaults)
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
