package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nutsdb/nutsdb"
)

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

// TestJiraJQLDBRoundTripAndExpiry covers the L2 (NutsDB) JQL cache directly:
// a persisted result round-trips, and a record older than the TTL is a miss.
func TestJiraJQLDBRoundTripAndExpiry(t *testing.T) {
	isolateLocalCache(t)

	ticket := &JiraTicket{Key: "DEVOPS-123"}
	ticket.Fields.Summary = "A ticket"
	ticket.Fields.Status.Name = "In Progress"

	key := jiraJQLCacheKey("you@example.com", "https://jira.example", "assignee = currentUser()")
	if err := saveJiraJQLToDB(key, JiraJQLResult{
		Tickets: map[string]*JiraTicket{"DEVOPS-123": ticket},
		OK:      true,
	}); err != nil {
		t.Fatal(err)
	}

	got, ok := loadJiraJQLFromDB(key)
	if !ok || !got.OK || len(got.Tickets) != 1 || got.Tickets["DEVOPS-123"].Fields.Summary != "A ticket" {
		t.Fatalf("L2 round trip failed: ok=%v got=%+v", ok, got)
	}

	// Backdate the stored record beyond the TTL — must become a miss.
	stale, err := json.Marshal(jiraJQLDBSnapshot{
		SavedAt: time.Now().Add(-jiraJQLCacheTTL - time.Minute),
		Tickets: map[string]*JiraTicket{"DEVOPS-123": ticket},
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := getCacheDB()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.NewBucket(nutsdb.DataStructureBTree, bucketMeta); err != nil && !isBucketExistsErr(err) {
		t.Fatal(err)
	}
	if err := tx.Put(bucketMeta, []byte(key), stale, 0); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if _, ok := loadJiraJQLFromDB(key); ok {
		t.Fatal("expired L2 JQL record was served")
	}
}
