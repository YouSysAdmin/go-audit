package event

import (
	"os/user"
	"sync"
)

// nameCache resolves ids to names and remembers the answers, failures included.
type nameCache struct {
	mu     sync.Mutex
	names  map[string]string
	lookup func(id string) (string, error)
}

func newUserCache() *nameCache {
	return &nameCache{
		names: make(map[string]string),
		lookup: func(id string) (string, error) {
			u, err := user.LookupId(id)
			if err != nil {
				return "", err
			}

			return u.Username, nil
		},
	}
}

func newGroupCache() *nameCache {
	return &nameCache{
		names: make(map[string]string),
		lookup: func(id string) (string, error) {
			g, err := user.LookupGroupId(id)
			if err != nil {
				return "", err
			}

			return g.Name, nil
		},
	}
}

// name returns the name for id, or "" when it cannot be resolved.
func (c *nameCache) name(id string) string {
	if id == "" || id == unsetID {
		return ""
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if name, ok := c.names[id]; ok {
		return name
	}

	name, err := c.lookup(id)
	if err != nil {
		name = ""
	}

	c.names[id] = name

	return name
}
