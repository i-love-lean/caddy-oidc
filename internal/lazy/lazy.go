// Package lazy provides one-shot lazy initialization of a value.
package lazy

import "sync"

// Lazy provides one-shot lazy initialization of a value T.
type Lazy[T any] struct {
	once  sync.Once
	init  func() (T, error)
	value T
	err   error
}

// New creates a new Lazy which when initialized for the first time calls the initialization function provided.
func New[T any](init func() (T, error)) *Lazy[T] {
	return &Lazy[T]{
		init: init,
	}
}

func (l *Lazy[T]) Get() (T, error) {
	l.once.Do(func() {
		l.value, l.err = l.init()
	})

	return l.value, l.err
}
