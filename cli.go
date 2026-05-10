package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const helpText = `clone - Interactive Repository Cloning and Management Tool

USAGE:
  clones [OPTIONS] [FILTER]

OPTIONS:
  -l, --local            Browse and manage only local repositories
  -r, --remote           Browse only remote repositories (exclude local)
  --platform <name>      Filter by platform: github or gitlab
  --jira                 Show only repos with active Jira tickets
  --no-cache             Bypass cache and fetch fresh data from APIs
  -h, --help             Show this help message

EXAMPLES:
  clones                        # Browse all repos (remote + local merged)
  clones terraform              # Filter repos by "terraform"
  clones -l                     # Browse only local repos
  clones -r                     # Browse only remote repos
  clones --platform gitlab      # Only GitLab repos (skips GitHub API)
  clones -l --platform gitlab   # Only local GitLab repos
  clones --jira                 # Only repos with active Jira tickets
  clones -l --jira              # Only local repos with active Jira tickets
  clones --no-cache             # Force refresh from APIs (bypass cache)
`

// parseArgs uses stdlib flag with two carry-over conventions from the
// hand-rolled parser:
//   - both -l and --local style work (stdlib flag treats them identically)
//   - the positional FILTER may appear before, between, or after flags
//
// To support the third point we pre-extract the first non-flag argument
// (skipping flag values like "github" after --platform) and pass the rest
// to flag.Parse.
func parseArgs() CliArgs {
	args := CliArgs{}

	// Flags whose next token is a value, not a positional.
	valueFlags := map[string]bool{"--platform": true, "-platform": true}

	var filter string
	var rest []string
	skip := false
	for _, a := range os.Args[1:] {
		if skip {
			rest = append(rest, a)
			skip = false
			continue
		}
		if valueFlags[a] {
			rest = append(rest, a)
			skip = true
			continue
		}
		if strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			continue
		}
		if filter == "" {
			filter = a
			continue
		}
		rest = append(rest, a)
	}
	args.Filter = filter

	fs := flag.NewFlagSet("clones", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, helpText) }

	fs.BoolVar(&args.LocalMode, "l", false, "browse local repos only")
	fs.BoolVar(&args.LocalMode, "local", false, "browse local repos only")
	fs.BoolVar(&args.RemoteOnly, "r", false, "browse remote repos only")
	fs.BoolVar(&args.RemoteOnly, "remote", false, "browse remote repos only")
	fs.BoolVar(&args.NoCache, "no-cache", false, "bypass cache")
	fs.BoolVar(&args.JiraFilter, "jira", false, "only repos with active Jira tickets")
	fs.StringVar(&args.Platform, "platform", "", "github|gitlab")

	if err := fs.Parse(rest); err != nil {
		os.Exit(2)
	}

	if args.Platform != "" {
		args.Platform = strings.ToLower(args.Platform)
		if args.Platform != "github" && args.Platform != "gitlab" {
			fmt.Fprintf(os.Stderr, "✗ Invalid platform: %s (must be 'github' or 'gitlab')\n", args.Platform)
			os.Exit(1)
		}
	}

	return args
}
