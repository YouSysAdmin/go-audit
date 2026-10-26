// Package output builds the destination that completed audit events are written to.
package output

import (
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"time"
)

const retryDelay = time.Second

// Writer JSON-encodes values to an underlying stream, one per line, retrying failed writes.
type Writer struct {
	mu         sync.Mutex
	e          *json.Encoder
	w          io.Writer
	attempts   int
	retryDelay time.Duration
	log        *slog.Logger
}

// NewWriter returns a Writer that tries each write up to attempts times.
func NewWriter(w io.Writer, attempts int, log *slog.Logger) *Writer {
	return &Writer{
		e:          json.NewEncoder(w),
		w:          w,
		attempts:   attempts,
		retryDelay: retryDelay,
		log:        log,
	}
}

// Write encodes v as one JSON line.
func (a *Writer) Write(v any) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var err error
	for i := range a.attempts {
		if err = a.e.Encode(v); err == nil {
			return nil
		}

		// The encoder keeps write errors, so a retry needs a new one
		a.e = json.NewEncoder(a.w)

		if i < a.attempts-1 {
			a.log.Warn("failed to write event, retrying", "attempt", i+1, "delay", a.retryDelay, "err", err)
			time.Sleep(a.retryDelay)
		}
	}

	return err
}

// swap replaces the underlying stream and returns the previous one.
func (a *Writer) swap(w io.Writer) io.Writer {
	a.mu.Lock()
	defer a.mu.Unlock()

	old := a.w
	a.w = w
	a.e = json.NewEncoder(w)

	return old
}

// Underlying returns the current stream.
func (a *Writer) Underlying() io.Writer {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.w
}
