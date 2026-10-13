package main

import (
	"os"
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

// TestCollectRepoPaths pins the v1.2.0 leaf-walk: a directory containing .git/
// is a repo AND a leaf. Depth-1 repos are collected (extractRepoFromPath rejects
// them later). Hidden dirs are still walked. Repos nested inside other repos,
// and anything under a skipScanDirNames dir, are not collected.
func TestCollectRepoPaths(t *testing.T) {
	root := t.TempDir()

	mkdir := func(parts ...string) string {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("mkdir %v: %v", parts, err)
		}
		return p
	}
	mkRepo := func(parts ...string) string {
		repo := mkdir(parts...)
		if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
			t.Fatalf("mkdir %v/.git: %v", parts, err)
		}
		return repo
	}

	// Collected: flat owner/repo, nested GitLab groups, depth-1 repo, a repo
	// that itself contains another repo, and repos under hidden dirs.
	mkRepo("octocat", "Hello-World")
	mkRepo("novatiq", "ops", "helm", "fusion")
	mkRepo("loose")
	mkRepo("withnested")
	mkRepo("hiddenroot", ".archive", "old-repo")

	// Not collected: a repo nested inside a repo, anything under a pruned junk
	// dir, and plain non-repo dirs.
	mkRepo("withnested", "sub", "inner-repo")
	mkdir("stray", "node_modules", "left-pad")
	mkRepo("stray", "node_modules", "left-pad", "oops")
	mkdir("docs")

	paths, walkFailed := collectRepoPaths(root)
	if walkFailed {
		t.Fatalf("collectRepoPaths reported a walk failure on a clean temp tree")
	}

	got := make(map[string]bool, len(paths))
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatalf("Rel(%q, %q): %v", root, p, err)
		}
		got[rel] = true
	}

	want := []string{
		"octocat/Hello-World",
		"novatiq/ops/helm/fusion",
		"loose",
		"withnested",
		"hiddenroot/.archive/old-repo",
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("expected repo %q to be collected; got %v", w, got)
		}
	}

	// must-not-collect: repo nested inside a repo, repo under a pruned junk dir
	absent := []string{
		"withnested/sub/inner-repo",
		"stray/node_modules/left-pad/oops",
	}
	for _, a := range absent {
		if got[a] {
			t.Errorf("repo %q must not be collected (leaf/junk skip); got %v", a, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("collected %d repos, want %d — unexpected extras: %v", len(got), len(want), got)
	}
}
