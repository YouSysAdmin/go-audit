// Package audit groups raw kernel audit netlink records into events.
package audit

import (
	"bytes"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Kernel audit record types go-audit treats specially.
// See include/uapi/linux/audit.h.
const (
	TypeSyscall   uint16 = 1300
	TypePath      uint16 = 1302
	TypeSockaddr  uint16 = 1306
	TypeCwd       uint16 = 1307
	TypeExecve    uint16 = 1309
	TypeEOE       uint16 = 1320 // End of multi record event
	TypeSeccomp   uint16 = 1326
	TypeProctitle uint16 = 1327
)

const (
	headerMinLength = 7               // Minimum length of an audit header
	headerStartPos  = 6               // Position in the audit header that the data starts
	completeAfter   = 2 * time.Second // Write a group after this time or EOE
)

// Message is a single kernel audit record.
type Message struct {
	Type      uint16 // Record type, see TypeName
	Data      string // Record text after the audit(...) header
	Seq       int    // Event sequence, shared by the records of one event
	AuditTime string // Event time as "seconds.millis"

	// Set by extra parsers while the process still exists
	ContainerID string
	CgroupRoot  string

	fields map[string]string
}

// Fields returns the parsed key value pairs of the record, parsed once.
func (m *Message) Fields() map[string]string {
	if m.fields == nil {
		m.fields = ParseFields(m.Type, m.Data)
	}

	return m.fields
}

// MessageGroup is every record sharing one audit sequence number.
type MessageGroup struct {
	Seq           int
	AuditTime     string
	CompleteAfter time.Time
	Msgs          []*Message

	// From the SYSCALL record, raw audit values
	Syscall string
	Arch    string
}

// NewMessageGroup starts a group from its first message.
func NewMessageGroup(am *Message) *MessageGroup {
	amg := &MessageGroup{
		Seq:           am.Seq,
		AuditTime:     am.AuditTime,
		CompleteAfter: time.Now().Add(completeAfter),
		Msgs:          make([]*Message, 0, 6),
	}

	amg.AddMessage(am)

	return amg
}

// NewMessage creates a Message from a netlink message.
func NewMessage(nlm *syscall.NetlinkMessage) *Message {
	aTime, seq := parseHeader(nlm)

	return &Message{
		Type:      nlm.Header.Type,
		Data:      string(nlm.Data),
		Seq:       seq,
		AuditTime: aTime,
	}
}

// parseHeader extracts the timestamp and sequence from an `audit(TIME:SEQ): ` prefix
// and strips the prefix from msg.Data. A malformed header yields seq 0.
func parseHeader(msg *syscall.NetlinkMessage) (ts string, seq int) {
	headerStop := bytes.IndexByte(msg.Data, ')')
	if headerStop < headerMinLength {
		return "", 0
	}

	header := string(msg.Data[:headerStop])
	if header[:headerStartPos] != "audit(" {
		return "", 0
	}

	sep := strings.IndexByte(header, ':')
	if sep < headerStartPos {
		return "", 0
	}

	ts = header[headerStartPos:sep]
	seq, _ = strconv.Atoi(header[sep+1:])

	// Skip the "): " that follows the header
	rest := min(headerStop+3, len(msg.Data))
	msg.Data = msg.Data[rest:]

	return ts, seq
}

// AddMessage appends a message to the group and records the syscall.
func (amg *MessageGroup) AddMessage(am *Message) {
	amg.Msgs = append(amg.Msgs, am)

	if am.Type == TypeSyscall {
		f := am.Fields()
		amg.Syscall = f["syscall"]
		amg.Arch = f["arch"]
	}
}
