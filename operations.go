package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// executeCD outputs the repository path for the shell wrapper to cd into
func executeCD(repo *Repository) {
	fmt.Println(repo.LocalPath)
}

// executePull pulls the latest changes from the remote repository.
// Honors remote.ops "pull" — runs natively on the remote host when configured.
func executePull(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Pulling latest changes for %s/%s...\n", repo.Owner, repo.Name)

	branch := getCurrentBranch(repo.LocalPath)
	if branch == "" {
		fmt.Fprintf(os.Stderr, "✗ Could not get current branch\n")
		os.Exit(1)
	}

	if err := runGitInRepo("pull", repo.LocalPath, "pull", "origin", branch); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to pull: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ Pulled latest changes\n")
	fmt.Println(repo.LocalPath)
}

// executePush pushes commits to the remote repository.
// Honors remote.ops "push" — runs natively on the remote host when configured.
func executePush(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Pushing commits for %s/%s...\n", repo.Owner, repo.Name)

	branch := getCurrentBranch(repo.LocalPath)
	if branch == "" {
		fmt.Fprintf(os.Stderr, "✗ Could not get current branch\n")
		os.Exit(1)
	}

	if err := runGitInRepo("push", repo.LocalPath, "push", "origin", branch); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to push: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ Pushed commits to origin/%s\n", branch)
	fmt.Println(repo.LocalPath)
}

// executeEdit signals to the shell wrapper to open the editor
func executeEdit(repo *Repository) {
	fmt.Printf("EDIT:%s\n", repo.LocalPath)
}

// executeCheckout lets user select and checkout a different branch
func executeCheckout(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Fetching branches for %s/%s...\n", repo.Owner, repo.Name)

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

	cmd = exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repo.LocalPath
	output, err = cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not get current branch: %v\n", err)
		os.Exit(1)
	}
	currentBranch := strings.TrimSpace(string(output))

	seen := make(map[string]bool)
	var uniqueBranches []string
	for _, branch := range branches {
		branch = strings.TrimSpace(branch)
		if branch == "" || branch == "HEAD" {
			continue
		}
		displayBranch := strings.TrimPrefix(branch, "origin/")
		if !seen[displayBranch] {
			seen[displayBranch] = true
			uniqueBranches = append(uniqueBranches, displayBranch)
		}
	}

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

	for _, branch := range uniqueBranches {
		if branch == currentBranch {
			_, _ = fmt.Fprintf(stdin, "\033[32m* %s\033[0m\n", branch)
		} else {
			// stdin is fzf's input pipe — fzf treats it as data rows to filter, not as commands.
			_, _ = stdin.Write([]byte(branch + "\n")) // nosemgrep: go.lang.security.audit.dangerous-command-write.dangerous-command-write
		}
	}
	_ = stdin.Close()

	output, err = io.ReadAll(stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not read fzf output: %v\n", err)
		os.Exit(1)
	}

	if err := fzfCmd.Wait(); err != nil {
		os.Exit(0)
	}

	selectedBranch := strings.TrimSpace(string(output))
	selectedBranch = strings.TrimPrefix(selectedBranch, "* ")

	if selectedBranch == "" {
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "Checking out %s...\n", selectedBranch)
	// Branch listing + fzf pick are local (cheap reads). Only the actual checkout
	// (which mutates the working tree) optionally goes via remote.
	if err := runGitInRepo("checkout", repo.LocalPath, "checkout", selectedBranch); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to checkout branch: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ Checked out %s\n", selectedBranch)

	fmt.Println(repo.LocalPath)
}

// executeDelete deletes a repository after confirmation
func executeDelete(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Delete %s/%s?\n", repo.Owner, repo.Name)
	fmt.Fprintf(os.Stderr, "Path: %s\n\n", repo.LocalPath)

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

	_, _ = stdin.Write([]byte("yes\nno\n"))
	_ = stdin.Close()

	output, err := io.ReadAll(stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not read fzf output: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Wait(); err != nil {
		os.Exit(0)
	}

	choice := strings.TrimSpace(string(output))
	if choice != "yes" {
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "Deleting %s...\n", repo.LocalPath)
	// Honors remote.ops "delete" — runs `rm -rf` natively on the remote when configured,
	// which sidesteps fuse-t / NFS silly-rename issues during git pack churn.
	if err := runRemove("delete", repo.LocalPath); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to delete repository: %v\n", err)
		os.Exit(1)
	}

	cleanupEmptyDirs(repo.LocalPath)

	fmt.Fprintf(os.Stderr, "✓ Deleted %s/%s\n", repo.Owner, repo.Name)
	os.Exit(0)
}

// cleanupEmptyDirs removes empty parent directories up to the configured clone root.
func cleanupEmptyDirs(repoPath string) {
	workDir := getSettings().CloneRoot
	currentDir := filepath.Dir(repoPath)

	for currentDir != workDir && strings.HasPrefix(currentDir, workDir) {
		if err := os.Remove(currentDir); err != nil {
			break
		}
		currentDir = filepath.Dir(currentDir)
	}
}

// selectJiraTicket returns the ticket ID the user wants to act on.
//   - 0 tickets: returns "" (caller should error out)
//   - 1 ticket: returns it directly with no UI
//   - 2+ tickets: pops an fzf picker showing each ticket's id, status, and summary,
//     then returns the chosen id ("" if cancelled).
//
// Status/summary for non-primary tickets are fetched on demand via fetchJiraTicket
// (which has its own in-process cache, so re-opens are fast).
func selectJiraTicket(repo *Repository) string {
	switch len(repo.JiraTicketIDs) {
	case 0:
		return ""
	case 1:
		return repo.JiraTicketIDs[0]
	}

	type row struct {
		id      string
		status  string
		summary string
	}
	rows := make([]row, 0, len(repo.JiraTicketIDs))
	for _, id := range repo.JiraTicketIDs {
		switch {
		case id == repo.JiraTicketID && repo.JiraStatus != "":
			rows = append(rows, row{id: id, status: repo.JiraStatus, summary: repo.JiraSummary})
		default:
			if t := fetchJiraTicket(id); t != nil {
				rows = append(rows, row{id: id, status: t.Fields.Status.Name, summary: t.Fields.Summary})
			} else {
				rows = append(rows, row{id: id, status: "?", summary: "(unable to fetch ticket details)"})
			}
		}
	}

	cmd := exec.Command("fzf",
		"--ansi",
		"--height=40%",
		"--reverse",
		"--header=Select Jira ticket | Ctrl-C to cancel",
		"--delimiter=\t",
		"--with-nth=1")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return ""
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ""
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return ""
	}

	for _, r := range rows {
		// Visible column (\t-delimited field 1): "DEVOPS-1162  [In Progress]  summary"
		// Hidden column (field 2): the bare ticket id, used for parsing back the selection.
		display := fmt.Sprintf("%-12s  [%s]  %s", r.id, r.status, sanitizeFzfField(r.summary))
		// stdin is fzf's input pipe — fzf treats it as data rows to filter, not as commands.
		_, _ = fmt.Fprintf(stdin, "%s\t%s\n", display, r.id) // nosemgrep: go.lang.security.audit.dangerous-command-write.dangerous-command-write
	}
	_ = stdin.Close()

	out, err := io.ReadAll(stdout)
	if err != nil {
		return ""
	}
	if err := cmd.Wait(); err != nil {
		return "" // user cancelled
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "\t")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// executeJiraOpen opens the Jira ticket in the default browser
func executeJiraOpen(repo *Repository) {
	_, baseURL, _ := getJiraConfig()
	if baseURL == "" {
		fmt.Fprintf(os.Stderr, "✗ Jira configuration not found\n")
		os.Exit(1)
	}

	ticketID := selectJiraTicket(repo)
	if ticketID == "" {
		os.Exit(0)
	}

	url := fmt.Sprintf("%s/browse/%s",
		strings.TrimSuffix(baseURL, "/"), ticketID)

	// runtime.GOOS is reliable; OSTYPE is a shell variable that isn't exported to subprocesses.
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		fmt.Fprintf(os.Stderr, "✗ Don't know how to open URLs on %s; visit %s manually\n", runtime.GOOS, url)
		os.Exit(1)
	}

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to open browser: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ Opening %s in browser...\n", url)

	fmt.Println(repo.LocalPath)
}

// executeJiraStatus displays detailed Jira ticket information
func executeJiraStatus(repo *Repository) {
	if len(repo.JiraTicketIDs) == 0 {
		fmt.Fprintf(os.Stderr, "✗ No Jira ticket associated with this repository\n")
		os.Exit(1)
	}

	ticketID := selectJiraTicket(repo)
	if ticketID == "" {
		os.Exit(0)
	}

	// Resolve status/summary for the chosen ticket. The primary ticket's data
	// is already on the Repository; for others, fetch it (cached in-process).
	var status, summary string
	switch {
	case ticketID == repo.JiraTicketID && repo.JiraStatus != "":
		status, summary = repo.JiraStatus, repo.JiraSummary
	default:
		if t := fetchJiraTicket(ticketID); t != nil {
			status, summary = t.Fields.Status.Name, t.Fields.Summary
		} else {
			status, summary = "?", "(unable to fetch ticket details)"
		}
	}

	fmt.Fprintf(os.Stderr, "\n\033[1mJira Ticket Details\033[0m\n")
	fmt.Fprintf(os.Stderr, "─────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "Ticket ID:    %s\n", ticketID)
	fmt.Fprintf(os.Stderr, "Status:       %s\n", status)
	fmt.Fprintf(os.Stderr, "Summary:      %s\n", summary)
	fmt.Fprintf(os.Stderr, "Branch:       %s\n", repo.CurrentBranch)
	fmt.Fprintf(os.Stderr, "Repository:   %s/%s\n", repo.Owner, repo.Name)
	fmt.Fprintf(os.Stderr, "Path:         %s\n", repo.LocalPath)
	fmt.Fprintf(os.Stderr, "─────────────────────────────────\n\n")

	fmt.Println(repo.LocalPath)
}

// performLocalOperation shows an operation menu and executes the selected operation
func performLocalOperation(repo *Repository) {
	// Widths chosen so the longest label ("jirastatus" = 10 chars) leaves a single
	// space gap, with everything else padded to match.
	operations := []string{
		"cd         Navigate to repository",
		"pull       Pull latest changes",
		"push       Push commits to remote",
		"checkout   Checkout a different branch",
		"delete     Delete repository",
		"edit       Open in $EDITOR",
	}

	if repo.JiraTicketID != "" && repo.JiraStatus != "" {
		operations = append(operations,
			"jiraopen   Open Jira ticket in browser",
			"jirastatus Show Jira ticket details",
		)
	}

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

	for _, op := range operations {
		// stdin is fzf's input pipe — fzf treats it as data rows to filter, not as commands.
		// `op` is a hardcoded label from the in-process operations slice.
		_, _ = stdin.Write([]byte(op + "\n")) // nosemgrep: go.lang.security.audit.dangerous-command-write.dangerous-command-write
	}
	_ = stdin.Close()

	output, err := io.ReadAll(stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not read fzf output: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Wait(); err != nil {
		os.Exit(0)
	}

	selectedLine := strings.TrimSpace(string(output))
	operation := strings.Fields(selectedLine)[0]

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
	case "jiraopen":
		executeJiraOpen(repo)
	case "jirastatus":
		executeJiraStatus(repo)
	default:
		os.Exit(0)
	}
}
