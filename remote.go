package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// shouldRunRemote reports whether the named operation should execute on the configured
// remote host instead of locally. Returns false when no Remote is configured.
func shouldRunRemote(op string) bool {
	r := getSettings().Remote
	if r == nil {
		return false
	}
	for _, o := range r.Ops {
		if o == op {
			return true
		}
	}
	return false
}

// toRemotePath translates a local path under CloneRoot into the corresponding path on
// the remote host. Returns an error when the input is not under CloneRoot — we never
// want to operate on paths the user didn't intend (e.g. accidentally rm-rf-ing /).
func toRemotePath(localPath string) (string, error) {
	settings := getSettings()
	if settings.Remote == nil {
		return "", fmt.Errorf("remote not configured")
	}
	rel, err := filepath.Rel(settings.CloneRoot, localPath)
	if err != nil {
		return "", fmt.Errorf("could not relativize %q against clone_root %q: %w", localPath, settings.CloneRoot, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside clone_root %q", localPath, settings.CloneRoot)
	}
	// Always use forward slashes on the remote side — assume Unix-y target.
	return path.Join(settings.Remote.Path, filepath.ToSlash(rel)), nil
}

// shellQuote single-quotes a string for safe inclusion in a remote shell command.
// SSH joins its arguments with spaces and feeds them to the remote login shell, so
// every path/value passed to ssh must be quoted by us — exec.Command's argv quoting
// only applies to the local ssh invocation, not the remote re-evaluation.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sshExec runs a shell command line on the configured remote host.
// The command line is a single string that the remote login shell evaluates, so the
// caller is responsible for shell-quoting any embedded paths or arguments.
// stdout and stderr are streamed to our stderr (matching local-execution conventions).
func sshExec(commandLine string) error {
	r := getSettings().Remote
	if r == nil {
		return fmt.Errorf("remote not configured")
	}
	cmd := exec.Command("ssh", r.Host, commandLine)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runGitInRepo runs `git -C <repoPath> <args...>` in the right context (local or remote)
// based on whether `op` is in the remote-ops whitelist. Streams output to stderr and
// returns the underlying command's exit status.
func runGitInRepo(op string, localRepoPath string, gitArgs ...string) error {
	if shouldRunRemote(op) {
		remotePath, err := toRemotePath(localRepoPath)
		if err != nil {
			return err
		}
		// Build: git -C '<remote>' arg1 arg2 ...
		parts := []string{"git", "-C", shellQuote(remotePath)}
		for _, a := range gitArgs {
			parts = append(parts, shellQuote(a))
		}
		return sshExec(strings.Join(parts, " "))
	}
	cmd := exec.Command("git", gitArgs...)
	cmd.Dir = localRepoPath
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runRemove deletes the repo path either via local os.RemoveAll or remote `rm -rf`.
// `op` must be the operation name to gate against remote.ops (typically "delete").
func runRemove(op string, localRepoPath string) error {
	if shouldRunRemote(op) {
		remotePath, err := toRemotePath(localRepoPath)
		if err != nil {
			return err
		}
		return sshExec("rm -rf " + shellQuote(remotePath))
	}
	return os.RemoveAll(localRepoPath)
}

// runClone runs `git clone -b <branch> <url> <localTarget>` either locally or on
// the remote (with the path translated). Ensures the parent directory exists in the
// chosen location.
func runClone(op string, localTarget, branch, url string) error {
	if shouldRunRemote(op) {
		remoteTarget, err := toRemotePath(localTarget)
		if err != nil {
			return err
		}
		remoteParent := path.Dir(remoteTarget)
		// `mkdir -p` is idempotent. Combined into one ssh round-trip with the clone.
		script := fmt.Sprintf("mkdir -p %s && git clone -b %s %s %s",
			shellQuote(remoteParent), shellQuote(branch), shellQuote(url), shellQuote(remoteTarget))
		return sshExec(script)
	}
	if err := os.MkdirAll(filepath.Dir(localTarget), 0755); err != nil {
		return err
	}
	cmd := exec.Command("git", "clone", "-b", branch, url, localTarget)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
