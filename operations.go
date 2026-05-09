package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// executeCD outputs the repository path for the shell wrapper to cd into
func executeCD(repo *Repository) {
	fmt.Println(repo.LocalPath)
}

// executePull pulls the latest changes from the remote repository
func executePull(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Pulling latest changes for %s/%s...\n", repo.Owner, repo.Name)

	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repo.LocalPath
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not get current branch: %v\n", err)
		os.Exit(1)
	}

	branch := strings.TrimSpace(string(output))

	cmd = exec.Command("git", "pull", "origin", branch)
	cmd.Dir = repo.LocalPath
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to pull: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "✓ Pulled latest changes\n")

	fmt.Println(repo.LocalPath)
}

// executePush pushes commits to the remote repository
func executePush(repo *Repository) {
	fmt.Fprintf(os.Stderr, "Pushing commits for %s/%s...\n", repo.Owner, repo.Name)

	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = repo.LocalPath
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ Could not get current branch: %v\n", err)
		os.Exit(1)
	}

	branch := strings.TrimSpace(string(output))

	cmd = exec.Command("git", "push", "origin", branch)
	cmd.Dir = repo.LocalPath
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
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
		os.Exit(0)
	}

	selectedBranch := strings.TrimSpace(string(output))
	selectedBranch = strings.TrimPrefix(selectedBranch, "* ")

	if selectedBranch == "" {
		os.Exit(0)
	}

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

	stdin.Write([]byte("yes\nno\n"))
	stdin.Close()

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
	if err := os.RemoveAll(repo.LocalPath); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to delete repository: %v\n", err)
		os.Exit(1)
	}

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
		if err := os.Remove(currentDir); err != nil {
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

	url := fmt.Sprintf("%s/browse/%s",
		strings.TrimSuffix(baseURL, "/"), repo.JiraTicketID)

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

	if repo.JiraTicketID != "" && repo.JiraStatus != "" {
		jiraOps := []string{
			"jira-open   Open Jira ticket in browser",
			"jira-status Show Jira ticket details",
		}
		operations = append(jiraOps, operations...)
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
		stdin.Write([]byte(op + "\n"))
	}
	stdin.Close()

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
	case "jira-open":
		executeJiraOpen(repo)
	case "jira-status":
		executeJiraStatus(repo)
	default:
		os.Exit(0)
	}
}
