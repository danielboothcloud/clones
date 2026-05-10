package main

import (
	"path/filepath"
	"testing"
)

func TestExtractRepoFromPath(t *testing.T) {
	work := filepath.Join("/", "home", "x", "projects", "work")

	cases := []struct {
		name      string
		repoPath  string
		wantOwner string
		wantName  string
	}{
		{
			name:      "github flat owner",
			repoPath:  filepath.Join(work, "octocat", "Hello-World"),
			wantOwner: "octocat",
			wantName:  "Hello-World",
		},
		{
			name:      "gitlab nested groups",
			repoPath:  filepath.Join(work, "ops", "terraform", "gcp", "syncserver", "syncserver"),
			wantOwner: "ops/terraform/gcp/syncserver",
			wantName:  "syncserver",
		},
		{
			name:      "single-segment path is rejected",
			repoPath:  filepath.Join(work, "loose-clone"),
			wantOwner: "",
			wantName:  "",
		},
		{
			// Pins current behavior: the function does not reject relative paths that
			// escape workDir via "..". filepath.Rel happily returns "../elsewhere/repo"
			// and the function uses it as-is. Tracked as a separate hardening item.
			name:      "path outside workdir is not rejected (current behavior)",
			repoPath:  filepath.Join(work, "..", "elsewhere", "repo"),
			wantOwner: "../elsewhere",
			wantName:  "repo",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			owner, name := extractRepoFromPath(c.repoPath, work)
			if owner != c.wantOwner || name != c.wantName {
				t.Fatalf("got owner=%q name=%q; want owner=%q name=%q",
					owner, name, c.wantOwner, c.wantName)
			}
		})
	}
}

func TestShouldExcludeRepo(t *testing.T) {
	cfg := &Config{ExcludePatterns: []string{
		"archived",
		"some-org/old-project",
		"github/personal/",
	}}

	cases := []struct {
		name string
		repo Repository
		want bool
	}{
		{
			name: "matches owner/name substring",
			repo: Repository{Owner: "some-org", Name: "old-project", Platform: "github"},
			want: true,
		},
		{
			name: "matches description substring",
			repo: Repository{Owner: "x", Name: "y", Description: "an archived demo", Platform: "github"},
			want: true,
		},
		{
			name: "matches platform/owner/name composite",
			repo: Repository{Owner: "personal", Name: "junk", Platform: "github"},
			want: true,
		},
		{
			name: "no match",
			repo: Repository{Owner: "active", Name: "thing", Description: "live service", Platform: "github"},
			want: false,
		},
		{
			name: "nil config",
			repo: Repository{Owner: "any", Name: "thing"},
			want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfgUsed := cfg
			if c.name == "nil config" {
				cfgUsed = nil
			}
			if got := shouldExcludeRepo(c.repo, cfgUsed); got != c.want {
				t.Fatalf("got=%v want=%v for repo=%+v", got, c.want, c.repo)
			}
		})
	}
}
