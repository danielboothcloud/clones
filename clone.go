package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func getDefaultBranch(repo *Repository) string {
	var token, url string

	if repo.Platform == "github" {
		token = getGitHubToken()
		url = fmt.Sprintf("%s/repos/%s/%s", githubAPIBase(), repo.Owner, repo.Name)
	} else {
		token = getGitLabToken()
		projectPath := strings.ReplaceAll(repo.Owner+"/"+repo.Name, "/", "%2F")
		url = fmt.Sprintf("https://%s/api/v4/projects/%s", getSettings().GitLabHost, projectPath)
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

	resp, err := doRequest(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return "main"
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		DefaultBranch string `json:"default_branch"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)

	if result.DefaultBranch == "" {
		return "main"
	}
	return result.DefaultBranch
}

func cloneOrUpdate(repo *Repository, branch string) string {
	homeDir, _ := os.UserHomeDir()
	targetDir := filepath.Join(homeDir, "projects", "work", repo.Owner, repo.Name)

	if _, err := os.Stat(targetDir); err == nil {
		if _, err := os.Stat(filepath.Join(targetDir, ".git")); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "✗ Directory exists but is not a git repository")
			os.Exit(1)
		}

		cmd := exec.Command("git", "branch", "--show-current")
		cmd.Dir = targetDir
		output, _ := cmd.Output()
		currentBranch := strings.TrimSpace(string(output))

		if currentBranch != branch {
			checkoutCmd := exec.Command("git", "checkout", branch)
			checkoutCmd.Dir = targetDir
			checkoutCmd.Stdout = nil
			checkoutCmd.Stderr = nil

			if err := checkoutCmd.Run(); err != nil {
				trackCmd := exec.Command("git", "checkout", "-t", "origin/"+branch)
				trackCmd.Dir = targetDir
				trackCmd.Stdout = nil
				trackCmd.Stderr = os.Stderr
				_ = trackCmd.Run()
			}
		}

		cmd = exec.Command("git", "pull")
		cmd.Dir = targetDir
		cmd.Stdout = nil
		cmd.Stderr = os.Stderr
		_ = cmd.Run()

		return targetDir
	}

	if err := os.MkdirAll(filepath.Dir(targetDir), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to create parent directory: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command("git", "clone", "-b", branch, cloneURL(repo), targetDir)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "✗ Failed to clone: %v\n", err)
		os.Exit(1)
	}

	return targetDir
}
