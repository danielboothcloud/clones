package main

// fetchAllPages fetches paginated API results using a bounded worker pool.
// It launches `workers` parallel page fetches at a time, then advances by `workers` pages
// until any page in a chunk returns fewer than `pageSize` results — that signals the end.
// Pages are returned in order.
//
// Trade-off vs the prior fixed-3-then-sequential approach: small accounts (<= workers pages)
// are no slower, and large accounts get full parallelism on every chunk instead of capping
// at the first 3.
//
// hardCap bounds total pages fetched as a runaway guard (a misbehaving API returning a full
// page forever would otherwise loop indefinitely).
func fetchAllPages(workers, pageSize int, fetch func(page int) []Repository) []Repository {
	if workers < 1 {
		workers = 1
	}
	const hardCap = 200

	var all []Repository
	nextPage := 1

	for nextPage <= hardCap {
		type res struct {
			page  int
			repos []Repository
		}
		ch := make(chan res, workers)
		for i := 0; i < workers; i++ {
			page := nextPage + i
			go func() {
				ch <- res{page: page, repos: fetch(page)}
			}()
		}

		ordered := make([][]Repository, workers)
		for i := 0; i < workers; i++ {
			r := <-ch
			ordered[r.page-nextPage] = r.repos
		}

		done := false
		for _, repos := range ordered {
			all = append(all, repos...)
			if len(repos) < pageSize {
				done = true
				break
			}
		}
		if done {
			return all
		}
		nextPage += workers
	}
	return all
}
