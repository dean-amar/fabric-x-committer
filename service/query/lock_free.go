package query

import (
	"context"

	"github.ibm.com/decentralized-trust-research/scalable-committer/utils"
)

// The following implementation is lock-free. It guarantees that for multiple parallel calls,
// at least one caller will make progress.
// A context is provided to avoid redundant work if the context is no longer relevant.
// We use lazy creation of the new value only if needed.
// That is, a new value is created using the create method only if a value is missing,
// or if it failed to update using the provided update method.
// Then, only if successfully assigned, we call the post method.
type (
	updateOrCreate[V any] struct {
		// create creates a new value.
		// It is used lazily, only if a value did not exist, or we failed to update it.
		// It should avoid any allocating resources that will leak if we fail
		// to assign the value.
		// Such resources should only be created via the post method, which
		// is called after a successful assignment.
		create func() *V
		// post is called if a value was successfully assigned.
		// It is used for heavier operations, or irreversible ones,
		// that we only want to do if the value was successfully assigned.
		post func(*V)
		// update is called to try to update the value.
		// If it fails, a new attempt is made to load/create a value.
		update func(*V) bool
	}
)

// mapUpdateOrCreate attempts to update or assign a key's value.
func mapUpdateOrCreate[K, V any](
	ctx context.Context, m *utils.SyncMap[K, *V], key K, methods updateOrCreate[V],
) (*V, error) {
	val, loaded := m.Load(key)
	for ctx.Err() == nil {
		// If there is a value, and we can update it, then return it.
		if loaded && val != nil {
			if methods.update(val) {
				return val, nil
			}
		}

		// Otherwise, let's try to assign a new value.
		newVal := methods.create()
		var assigned bool
		if !loaded {
			val, loaded = m.LoadOrStore(key, newVal)
			assigned = !loaded
		} else if assigned = m.CompareAndSwap(key, val, newVal); !assigned {
			// If the CAS failed, we need to load the new value.
			val, loaded = m.Load(key)
		}

		if assigned {
			methods.post(newVal)
			val = newVal
			loaded = true
		}
	}

	// We only reach here if the context ended.
	return nil, ctx.Err()
}
