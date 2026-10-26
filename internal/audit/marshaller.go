package audit

import (
	"log/slog"
	"syscall"
	"time"
)

// Writer receives completed message groups.
type Writer interface {
	Write(msg *MessageGroup) error
}

// ExtraParser enriches a message with data from outside the audit record.
type ExtraParser interface {
	Parse(am *Message)
}

// Options controls which events are kept and how sequence gaps are reported.
type Options struct {
	EventMin      uint16
	EventMax      uint16
	TrackMessages bool
	LogOutOfOrder bool
	MaxOutOfOrder int
}

// Marshaller groups audit records by sequence and writes complete groups.
// It is not safe for concurrent use.
type Marshaller struct {
	msgs     map[int]*MessageGroup
	writer   Writer
	lastSeq  int
	missed   map[int]bool
	worstLag int
	opts     Options
	filters  filterSet
	parsers  []ExtraParser
	log      *slog.Logger
}

// NewMarshaller returns a Marshaller writing to w.
func NewMarshaller(w Writer, opts Options, filters []Filter, parsers []ExtraParser, log *slog.Logger) *Marshaller {
	return &Marshaller{
		writer:  w,
		msgs:    make(map[int]*MessageGroup, 5), // Rarely more than 2 groups in flight
		missed:  make(map[int]bool, 10),
		opts:    opts,
		filters: newFilterSet(filters),
		parsers: parsers,
		log:     log,
	}
}

// Consume ingests a netlink message. It returns an error only when writing
// a completed group fails.
func (a *Marshaller) Consume(nlMsg *syscall.NetlinkMessage) error {
	aMsg := NewMessage(nlMsg)

	if aMsg.Seq == 0 {
		// Invalid audit message, only flush what is due
		return a.FlushOld()
	}

	if a.opts.TrackMessages {
		a.detectMissing(aMsg.Seq)
	}

	switch {
	case nlMsg.Header.Type < a.opts.EventMin || nlMsg.Header.Type > a.opts.EventMax:
		return a.FlushOld()
	case nlMsg.Header.Type == TypeEOE:
		// End of event, flush the group with this sequence and discard this message
		return a.completeMessage(aMsg.Seq)
	}

	if group, ok := a.msgs[aMsg.Seq]; ok {
		group.AddMessage(aMsg)
	} else {
		a.msgs[aMsg.Seq] = NewMessageGroup(aMsg)
	}

	for _, p := range a.parsers {
		p.Parse(aMsg)
	}

	return a.FlushOld()
}

// FlushOld writes groups that waited long enough. Kaudit gives no signal for
// the end of single-message events, so age is the only completion trigger.
func (a *Marshaller) FlushOld() error {
	now := time.Now()
	for seq, msg := range a.msgs {
		if !msg.CompleteAfter.After(now) {
			if err := a.completeMessage(seq); err != nil {
				return err
			}
		}
	}

	return nil
}

// Flush writes every pending group regardless of age.
func (a *Marshaller) Flush() error {
	for seq := range a.msgs {
		if err := a.completeMessage(seq); err != nil {
			return err
		}
	}

	return nil
}

// Pending returns the number of groups not yet written.
func (a *Marshaller) Pending() int {
	return len(a.msgs)
}

// completeMessage removes the group of seq and writes it unless a filter drops it.
func (a *Marshaller) completeMessage(seq int) error {
	msg, ok := a.msgs[seq]
	if !ok {
		return nil
	}

	delete(a.msgs, seq)

	if a.filters.drop(msg) {
		return nil
	}

	return a.writer.Write(msg)
}

// detectMissing tracks sequence numbers and logs suspected gaps.
func (a *Marshaller) detectMissing(seq int) {
	if seq > a.lastSeq+1 && a.lastSeq != 0 {
		// Possibly skipped some, wait for later sequences before reporting
		for i := a.lastSeq + 1; i < seq; i++ {
			a.missed[i] = true
		}
	}

	for missedSeq := range a.missed {
		switch {
		case missedSeq == seq:
			lag := a.lastSeq - missedSeq
			a.worstLag = max(a.worstLag, lag)

			if a.opts.LogOutOfOrder {
				a.log.Warn("sequence arrived out of order", "seq", missedSeq, "lag", lag, "worst_lag", a.worstLag)
			}

			delete(a.missed, missedSeq)
		case seq-missedSeq > a.opts.MaxOutOfOrder:
			a.log.Warn("likely missed sequence", "seq", missedSeq, "current", seq, "worst_lag", a.worstLag)
			delete(a.missed, missedSeq)
		}
	}

	a.lastSeq = max(a.lastSeq, seq)
}
