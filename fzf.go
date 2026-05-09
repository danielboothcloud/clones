package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

func selectRepoWithFzf(repoChan <-chan Repository) *Repository {
	// Format in stdin: [GitHub] owner/name\tstars\tlanguage\tdescription\tplatform
	// or [Local: GitHub] owner/name\tstars\tlanguage\tdescription\tplatform
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

	if err := cmd.Start(); err != nil {
		return nil
	}

	var repos []Repository
	var mu sync.Mutex

	go func() {
		defer func() { _ = stdin.Close() }()
		for repo := range repoChan {
			mu.Lock()
			repos = append(repos, repo)
			mu.Unlock()

			var platformTag, color string
			if repo.LocalPath != "" {
				switch repo.Platform {
				case "github":
					platformTag, color = "[Local: GitHub]", "\033[32m"
				case "gitlab":
					platformTag, color = "[Local: GitLab]", "\033[32m"
				default:
					platformTag, color = "[Local]", "\033[32m"
				}
			} else {
				if repo.Platform == "gitlab" {
					platformTag, color = "[GitLab]", "\033[33m"
				} else {
					platformTag, color = "[GitHub]", "\033[34m"
				}
			}

			repoName := repo.Owner + "/" + repo.Name
			if repo.IsDirty {
				repoName = repoName + " \033[31m*\033[0m"
			}
			if repo.HasUnpushed {
				repoName = repoName + " \033[33m^\033[0m"
			}

			if repo.LocalPath != "" && len(repo.JiraTicketIDs) > 0 {
				ticketsList := strings.Join(repo.JiraTicketIDs, ", ")

				if repo.JiraStatus != "" {
					var statusColor string
					switch {
					case isActiveJiraStatus(repo.JiraStatus):
						statusColor = "\033[32m"
					case repo.JiraStatus == "Done" || repo.JiraStatus == "Closed":
						statusColor = "\033[90m"
					default:
						statusColor = "\033[36m"
					}
					repoName = repoName + fmt.Sprintf(" %s[%s: %s]\033[0m",
						statusColor, ticketsList, repo.JiraStatus)
				} else {
					repoName = repoName + fmt.Sprintf(" \033[35m[%s]\033[0m", ticketsList)
				}
			}

			line := fmt.Sprintf("%s%s\033[0m %s\t%d\t%s\t%s\t%s\n",
				color, platformTag, repoName,
				repo.Stars, repo.Language, repo.Description, repo.Platform)
			_, _ = stdin.Write([]byte(line))
		}
	}()

	output, err := io.ReadAll(stdout)
	if err != nil {
		return nil
	}

	if err := cmd.Wait(); err != nil {
		return nil
	}

	ownerName := parseFzfRowOwnerName(strings.TrimSpace(string(output)))
	if ownerName == "" {
		return nil
	}

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

// parseFzfRowOwnerName extracts owner/name from a row that fzf wrote out as the user's
// selection. The row was originally formatted by selectRepoWithFzf as:
//
//	[GitHub] owner/name\t<stars>\t<lang>\t<desc>\t<platform>
//	[Local: GitHub] owner/name <indicators>\t<stars>\t<lang>\t<desc>\t<platform>
//
// Indicators are: " *" (dirty), " ^" (unpushed), " [TICKET-1, TICKET-2: Status]" (Jira).
// fzf's --ansi mode strips color codes from the selection it returns.
//
// Returns "" when the row can't be parsed (malformed, empty, etc.).
var fzfRowJiraSuffix = regexp.MustCompile(` \[([^\]]+)\]`)

func parseFzfRowOwnerName(line string) string {
	if line == "" {
		return ""
	}
	mainPart := strings.Split(line, "\t")[0]
	mainPart = fzfRowJiraSuffix.ReplaceAllString(mainPart, "")
	mainPart = strings.ReplaceAll(mainPart, " *", "")
	mainPart = strings.ReplaceAll(mainPart, " ^", "")

	parts := strings.Fields(mainPart)
	if len(parts) < 2 {
		return ""
	}
	// "[GitHub] owner/name"      -> parts[0]="[GitHub]",  parts[1]="owner/name"
	// "[Local: GitHub] owner/name" -> parts[0]="[Local:", parts[1]="GitHub]", parts[2]="owner/name"
	if len(parts) >= 3 && strings.HasSuffix(parts[1], "]") {
		return parts[2]
	}
	return parts[1]
}

func selectBranchWithFzf(repo *Repository, defaultBranch string) string {
	var token, url string

	if repo.Platform == "github" {
		token = getGitHubToken()
		url = fmt.Sprintf("%s/repos/%s/%s/branches", githubAPIBase(), repo.Owner, repo.Name)
	} else {
		token = getGitLabToken()
		projectPath := strings.ReplaceAll(repo.Owner+"/"+repo.Name, "/", "%2F")
		url = fmt.Sprintf("https://%s/api/v4/projects/%s/repository/branches", getSettings().GitLabHost, projectPath)
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

	resp, err := doRequest(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return defaultBranch
	}
	defer func() { _ = resp.Body.Close() }()

	var branches []struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&branches)

	if len(branches) == 0 {
		return defaultBranch
	}

	var branchNames []string
	for _, b := range branches {
		branchNames = append(branchNames, b.Name)
	}

	// Sort branches: main/master first if they exist
	var sortedBranches []string
	var hasMain, hasMaster bool
	var otherBranches []string

	for _, name := range branchNames {
		switch name {
		case "main":
			hasMain = true
		case "master":
			hasMaster = true
		default:
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

	if len(branchNames) == 1 {
		return branchNames[0]
	}

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
