package audit

import (
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func newNetlinkMessage(typ uint16, data string) *syscall.NetlinkMessage {
	return &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Len: 44, Type: typ},
		Data:   []byte(data),
	}
}

func TestNewMessage(t *testing.T) {
	am := NewMessage(newNetlinkMessage(TypeExecve, "audit(10000001:99): hi there"))
	assert.Equal(t, TypeExecve, am.Type)
	assert.Equal(t, 99, am.Seq)
	assert.Equal(t, "10000001", am.AuditTime)
	assert.Equal(t, "hi there", am.Data)
}

func TestParseHeaderMalformed(t *testing.T) {
	for _, data := range []string{
		"",
		"hi there",
		"audit(1)",
		"audit(10000001): no separator",
		"notaud(1:2): wrong prefix",
	} {
		t.Run(data, func(t *testing.T) {
			am := NewMessage(newNetlinkMessage(TypeSyscall, data))
			assert.Equal(t, 0, am.Seq)
		})
	}
}

func TestParseHeaderNoBody(t *testing.T) {
	am := NewMessage(newNetlinkMessage(TypeSyscall, "audit(10000001:5)"))
	assert.Equal(t, 5, am.Seq)
	assert.Empty(t, am.Data)
}

func TestNewMessageGroup(t *testing.T) {
	m := &Message{Type: TypeSyscall, Seq: 1019, AuditTime: "9919", Data: "arch=c000003e syscall=59 success=yes"}

	amg := NewMessageGroup(m)
	assert.Equal(t, 1019, amg.Seq)
	assert.Equal(t, "9919", amg.AuditTime)
	assert.True(t, amg.CompleteAfter.After(time.Now()), "complete after should be in the future")
	assert.Equal(t, []*Message{m}, amg.Msgs)
	assert.Equal(t, "59", amg.Syscall)
	assert.Equal(t, "c000003e", amg.Arch)

	// Only the SYSCALL record sets the syscall
	amg.AddMessage(&Message{Type: TypeCwd, Data: "cwd=\"/\" syscall=1"})
	assert.Len(t, amg.Msgs, 2)
	assert.Equal(t, "59", amg.Syscall)
}

func TestTypeName(t *testing.T) {
	assert.Equal(t, "SYSCALL", TypeName(TypeSyscall))
	assert.Equal(t, "PROCTITLE", TypeName(TypeProctitle))
	assert.Equal(t, "USER_LOGIN", TypeName(1112))
	assert.Equal(t, "UNKNOWN[1999]", TypeName(1999))

	id, ok := TypeID("USER_END")
	assert.True(t, ok)
	assert.Equal(t, uint16(1106), id)

	_, ok = TypeID("NOPE")
	assert.False(t, ok)
}
