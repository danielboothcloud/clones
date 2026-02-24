#!/bin/zsh
# Shell wrapper for the clones tool
# This function automatically changes directory after cloning
#
# Installation:
#   1. Build the Go binary: go build -o ~/.local/bin/clones
#   2. Add this to your ~/.zshrc:
#      source /path/to/clone.zsh
#   3. Reload your shell: source ~/.zshrc
#
# Usage:
#   clones    # Interactive mode with automatic cd

clones() {
  # Don't capture stderr - let git output show in real-time
  local target_dir
  target_dir=$(command clones "$@")
  local exit_code=$?

  # Check if this is an edit command
  if [[ $target_dir == EDIT:* ]]; then
    local repo_path="${target_dir#EDIT:}"
    if [[ -d "$repo_path" ]]; then
      cd "$repo_path" || return 1
      ${EDITOR:-vi} .
      echo ""
      echo "Changed directory to: $repo_path"
      if [[ -d .git ]]; then
        echo ""
        git status -sb
      fi
    fi
    return
  fi

  # If successful, cd into the directory
  if [[ $exit_code -eq 0 && -d "$target_dir" ]]; then
    cd "$target_dir" || return 1
    echo ""
    echo "Changed directory to: $target_dir"

    # Show git status if in a git repository
    if [[ -d .git ]]; then
      echo ""
      git status -sb
    fi
  fi
}
