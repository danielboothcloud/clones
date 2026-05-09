package main

import (
	"fmt"
	"strings"
	"testing"
)

// renderFzfRow mirrors the row format selectRepoWithFzf streams into fzf,
// minus ANSI color codes (fzf --ansi strips those from the selected output).
// Kept in the test file so any drift between the writer and the parser is caught.
func renderFzfRow(repo Repository) string {
	var platformTag string
	if repo.LocalPath != "" {
		switch repo.Platform {
		case "github":
			platformTag = "[Local: GitHub]"
		case "gitlab":
			platformTag = "[Local: GitLab]"
		default:
			platformTag = "[Local]"
		}
	} else {
		switch repo.Platform {
		case "gitlab":
			platformTag = "[GitLab]"
		default:
			platformTag = "[GitHub]"
		}
	}

	repoName := repo.Owner + "/" + repo.Name
	if repo.IsDirty {
		repoName += " *"
	}
	if repo.HasUnpushed {
		repoName += " ^"
	}
	if repo.LocalPath != "" && len(repo.JiraTicketIDs) > 0 {
		ticketsList := strings.Join(repo.JiraTicketIDs, ", ")
		if repo.JiraStatus != "" {
			repoName += fmt.Sprintf(" [%s: %s]", ticketsList, repo.JiraStatus)
		} else {
			repoName += fmt.Sprintf(" [%s]", ticketsList)
		}
	}

	return fmt.Sprintf("%s %s\t%d\t%s\t%s\t%s",
		platformTag, repoName, repo.Stars, repo.Language, repo.Description, repo.Platform)
}

func TestParseFzfRowOwnerName_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		repo Repository
		want string
	}{
		{
			name: "github remote",
			repo: Repository{Platform: "github", Owner: "octocat", Name: "Hello-World", Stars: 5, Language: "Go", Description: "demo"},
			want: "octocat/Hello-World",
		},
		{
			name: "gitlab nested groups",
			repo: Repository{Platform: "gitlab", Owner: "ops/terraform/gcp/syncserver", Name: "syncserver", Stars: 0, Language: "Unknown", Description: "infra"},
			want: "ops/terraform/gcp/syncserver/syncserver",
		},
		{
			name: "local github with dirty + unpushed + jira status",
			repo: Repository{
				Platform: "github", Owner: "me", Name: "thing", LocalPath: "/x",
				IsDirty: true, HasUnpushed: true,
				JiraTicketIDs: []string{"PROJ-1", "PROJ-2"}, JiraStatus: "In Progress",
			},
			want: "me/thing",
		},
		{
			name: "local gitlab no jira status (just ticket id)",
			repo: Repository{
				Platform: "gitlab", Owner: "team/sub", Name: "lib", LocalPath: "/x",
				JiraTicketIDs: []string{"ABC-9"},
			},
			want: "team/sub/lib",
		},
		{
			name: "remote gitlab",
			repo: Repository{Platform: "gitlab", Owner: "g", Name: "l", Stars: 1},
			want: "g/l",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			row := renderFzfRow(c.repo)
			got := parseFzfRowOwnerName(row)
			if got != c.want {
				t.Fatalf("round-trip failed:\n  row:  %q\n  got:  %q\n  want: %q", row, got, c.want)
			}
		})
	}
}

func TestParseFzfRowOwnerName_Empty(t *testing.T) {
	if got := parseFzfRowOwnerName(""); got != "" {
		t.Fatalf("expected empty result, got %q", got)
	}
	if got := parseFzfRowOwnerName("[GitHub]"); got != "" {
		t.Fatalf("expected empty result for malformed row, got %q", got)
	}
}
