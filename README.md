# clones

Interactive CLI for cloning and managing Git repos from GitHub and GitLab. Uses `fzf` for fuzzy finding, NutsDB for caching, and optional Jira integration for ticket labels.

## Install

```bash
go build -o ~/.local/bin/clones .
source /path/to/clone/clone.zsh  # add to ~/.zshrc for auto-cd
```

Requires `fzf`, `git`, and auth via `gh auth login` / `glab auth login` (or `GITHUB_TOKEN` / `GITLAB_TOKEN` env vars).

## Usage

```bash
clones                       # browse all repos (remote + local)
clones terraform             # filter by name
clones -l                    # local repos only (cd, pull, push, delete, edit)
clones -r                    # remote repos only
clones --platform gitlab     # single platform
clones --no-cache            # bypass NutsDB cache
clones --jira                # only repos with active Jira tickets
```

Repos clone to `~/projects/work/<owner>/<repo>`. The shell wrapper auto-cds after selection.

## Cache

Repos are cached in NutsDB at `~/.cache/clones/db/` with 24h TTL. Stale cache is served instantly while a background refresh runs for next time.

## Jira Integration

Optional. Configure `~/.config/clones/jira.yml`:

```yaml
enabled: true
base_url: https://yourorg.atlassian.net
email: you@example.com
jql: assignee = currentUser() AND status not in (Closed, Done, Completed)
active_statuses: In Progress, In Review, To Do, Pending
```

When enabled, local repos show Jira ticket labels extracted from branch names (e.g. `feature/PROJ-123` shows `[PROJ-123]`). The JQL filter controls which tickets are displayed. Set `enabled: false` or remove the file to disable.

