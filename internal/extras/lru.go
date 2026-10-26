package extras

import "container/list"

// cache is a fixed size key value store. Not safe for concurrent use.
type cache[K comparable, V any] interface {
	Add(key K, value V)
	Get(key K) (V, bool)
	Size() int
}

// newCache returns an LRU cache when size is above zero and a no-op cache otherwise.
func newCache[K comparable, V any](size int) cache[K, V] {
	if size > 0 {
		return &lru[K, V]{size: size, ll: list.New(), items: make(map[K]*list.Element, size)}
	}

	return noCache[K, V]{}
}

// noCache stores nothing, used when the cache size is 0.
type noCache[K comparable, V any] struct{}

func (noCache[K, V]) Add(K, V) {}

func (noCache[K, V]) Get(K) (V, bool) {
	var zero V

	return zero, false
}

func (noCache[K, V]) Size() int { return 0 }

type lruEntry[K comparable, V any] struct {
	key   K
	value V
}

// lru evicts the least recently used entry when it grows past size.
type lru[K comparable, V any] struct {
	size  int
	ll    *list.List
	items map[K]*list.Element
}

func (c *lru[K, V]) Add(key K, value V) {
	if e, ok := c.items[key]; ok {
		c.ll.MoveToFront(e)
		e.Value.(*lruEntry[K, V]).value = value

		return
	}

	c.items[key] = c.ll.PushFront(&lruEntry[K, V]{key: key, value: value})

	if c.ll.Len() > c.size {
		oldest := c.ll.Back()
		c.ll.Remove(oldest)
		delete(c.items, oldest.Value.(*lruEntry[K, V]).key)
	}
}

func (c *lru[K, V]) Get(key K) (V, bool) {
	e, ok := c.items[key]
	if !ok {
		var zero V

		return zero, false
	}

	c.ll.MoveToFront(e)

	return e.Value.(*lruEntry[K, V]).value, true
}

func (c *lru[K, V]) Size() int { return c.size }
