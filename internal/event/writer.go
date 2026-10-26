package event

import "github.com/yousysadmin/go-audit/internal/audit"

// Encoder writes one value as one output line.
type Encoder interface {
	Write(v any) error
}

// Writer builds an event from each completed group and hands it to an Encoder.
type Writer struct {
	b   *Builder
	out Encoder
}

// NewWriter returns a Writer, it satisfies audit.Writer.
func NewWriter(b *Builder, out Encoder) *Writer {
	return &Writer{b: b, out: out}
}

// Write builds and encodes the event of g.
func (w *Writer) Write(g *audit.MessageGroup) error {
	return w.out.Write(w.b.Build(g))
}

var _ audit.Writer = (*Writer)(nil)
