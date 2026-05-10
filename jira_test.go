package main

import "testing"

// TestExtractJiraTicketID pins current behavior. Note two quirks worth fixing
// in a separate change:
//   - When a branch part contains a ticket plus extra suffix (e.g. PROJ-456-some-fix),
//     the function returns the whole part rather than just PROJ-456. The MatchString
//     guard returns part as-is and never reaches the FindString fall-through.
//   - The regex is unanchored so any "<letters>-<digits>" sequence in a longer word
//     can be picked up.
func TestExtractJiraTicketID(t *testing.T) {
	cases := []struct {
		branch string
		want   string
	}{
		{"PROJ-123", "PROJ-123"},
		{"feature/PROJ-123", "PROJ-123"},
		{"bugfix/PROJ-456-some-fix", "PROJ-456-some-fix"}, // current behavior
		{"hotfix/abc-789", "abc-789"},
		{"release/abc-12-other", "abc-12-other"}, // current behavior
		{"main", ""},
		{"feature/no-ticket-here", ""}, // no digits → no match
		{"chore/PROJ-1/cleanup", "PROJ-1"},
	}

	for _, c := range cases {
		t.Run(c.branch, func(t *testing.T) {
			if got := extractJiraTicketID(c.branch); got != c.want {
				t.Fatalf("extractJiraTicketID(%q) = %q, want %q", c.branch, got, c.want)
			}
		})
	}
}
