package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// jsonWriter encodes a compact view of each group, for assertions.
type jsonWriter struct{ e *json.Encoder }

func newJSONWriter(w io.Writer) *jsonWriter { return &jsonWriter{e: json.NewEncoder(w)} }

type recordView struct {
	Type uint16 `json:"type"`
	Data string `json:"data"`
}

type groupView struct {
	Seq       int          `json:"sequence"`
	AuditTime string       `json:"timestamp"`
	Msgs      []recordView `json:"messages"`
}

func (w *jsonWriter) Write(msg *MessageGroup) error {
	v := groupView{Seq: msg.Seq, AuditTime: msg.AuditTime}
	for _, m := range msg.Msgs {
		v.Msgs = append(v.Msgs, recordView{Type: m.Type, Data: m.Data})
	}

	return w.e.Encode(v)
}

type failWriter struct{}

func (failWriter) Write(*MessageGroup) error { return errors.New("derp") }

func newEOE(seq string) *syscall.NetlinkMessage {
	return newNetlinkMessage(TypeEOE, "audit(10000001:"+seq+"): ")
}

func TestMarshallerConsume(t *testing.T) {
	w := &bytes.Buffer{}
	m := NewMarshaller(newJSONWriter(w), Options{EventMin: 1100, EventMax: 1399}, nil, nil, discard)

	// Flush group on 1320
	assert.NoError(t, m.Consume(newNetlinkMessage(1300, "audit(10000001:1): hi there")))
	assert.NoError(t, m.Consume(newNetlinkMessage(1301, "audit(10000001:1): hi there")))
	assert.NoError(t, m.Consume(newEOE("1")))

	assert.Equal(t,
		"{\"sequence\":1,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1300,\"data\":\"hi there\"},{\"type\":1301,\"data\":\"hi there\"}]}\n",
		w.String(),
	)
	assert.Equal(t, 0, m.Pending())

	// Ignore below 1100
	assert.NoError(t, m.Consume(newNetlinkMessage(1099, "audit(10000001:2): hi there")))
	assert.Equal(t, 0, m.Pending())

	// Ignore above 1399
	assert.NoError(t, m.Consume(newNetlinkMessage(1400, "audit(10000001:3): hi there")))
	assert.Equal(t, 0, m.Pending())

	// Ignore sequences of 0
	assert.NoError(t, m.Consume(newNetlinkMessage(1300, "audit(10000001:0): hi there")))
	assert.Equal(t, 0, m.Pending())
}

func TestMarshallerFlushesOldGroups(t *testing.T) {
	w := &bytes.Buffer{}
	m := NewMarshaller(newJSONWriter(w), Options{EventMin: 1100, EventMax: 1399}, nil, nil, discard)

	assert.NoError(t, m.Consume(newNetlinkMessage(1300, "audit(10000001:4): hi there")))
	assert.NoError(t, m.FlushOld())
	assert.Equal(t, 1, m.Pending(), "a fresh group should not be flushed")

	// Age the group instead of waiting for it
	m.msgs[4].CompleteAfter = time.Now().Add(-time.Millisecond)
	assert.NoError(t, m.FlushOld())

	assert.Equal(t, "{\"sequence\":4,\"timestamp\":\"10000001\",\"messages\":[{\"type\":1300,\"data\":\"hi there\"}]}\n", w.String())
	assert.Equal(t, 0, m.Pending())
}

func TestMarshallerFlush(t *testing.T) {
	w := &bytes.Buffer{}
	m := NewMarshaller(newJSONWriter(w), Options{EventMin: 1100, EventMax: 1399}, nil, nil, discard)

	assert.NoError(t, m.Consume(newNetlinkMessage(1300, "audit(10000001:5): one")))
	assert.NoError(t, m.Consume(newNetlinkMessage(1300, "audit(10000001:6): two")))
	assert.Equal(t, 2, m.Pending())

	assert.NoError(t, m.Flush())
	assert.Equal(t, 0, m.Pending())
	assert.Contains(t, w.String(), "\"sequence\":5")
	assert.Contains(t, w.String(), "\"sequence\":6")
}

func TestMarshallerWriteError(t *testing.T) {
	m := NewMarshaller(failWriter{}, Options{EventMin: 1300, EventMax: 1399}, nil, nil, discard)

	assert.NoError(t, m.Consume(newNetlinkMessage(1300, "audit(10000001:4): hi there")))
	assert.EqualError(t, m.Consume(newEOE("4")), "derp")
}

func TestMarshallerFiltersBySyscallName(t *testing.T) {
	w := &bytes.Buffer{}
	filters := []Filter{{Syscall: "connect", MessageType: TypeSockaddr, Regex: regexp.MustCompile(`saddr=01`)}}
	m := NewMarshaller(newJSONWriter(w), Options{EventMin: 1300, EventMax: 1399}, filters, nil, discard)

	// x86_64 connect is 42
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSyscall, "audit(1:1): arch=c000003e syscall=42 success=yes")))
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSockaddr, "audit(1:1): saddr=01002F746D70")))
	assert.NoError(t, m.Consume(newEOE("1")))

	// aarch64 connect is 203
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSyscall, "audit(1:2): arch=c00000b7 syscall=203 success=yes")))
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSockaddr, "audit(1:2): saddr=01002F746D70")))
	assert.NoError(t, m.Consume(newEOE("2")))
	assert.Empty(t, w.String())

	// 42 on aarch64 is not connect
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSyscall, "audit(1:3): arch=c00000b7 syscall=42 success=yes")))
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSockaddr, "audit(1:3): saddr=01002F746D70")))
	assert.NoError(t, m.Consume(newEOE("3")))
	assert.Contains(t, w.String(), "\"sequence\":3")
}

func TestMarshallerFilterAnyRecordType(t *testing.T) {
	w := &bytes.Buffer{}
	filters := []Filter{{Regex: regexp.MustCompile(`terminal=cron`)}}
	m := NewMarshaller(newJSONWriter(w), Options{EventMin: 1100, EventMax: 1399}, filters, nil, discard)

	// Every PAM record of a cron session is dropped, whatever its type
	for i, typ := range []uint16{1101, 1103, 1105, 1104, 1106} {
		seq := strconv.Itoa(i + 1)
		assert.NoError(t, m.Consume(newNetlinkMessage(typ, "audit(1:"+seq+"): pid=1 uid=0 auid=999 msg='op=PAM:session_close acct=\"cwagent\" exe=\"/usr/sbin/cron\" terminal=cron res=success'")))
	}

	// A login over ssh is kept
	assert.NoError(t, m.Consume(newNetlinkMessage(1106, "audit(1:9): pid=2 uid=0 auid=1000 msg='op=PAM:session_close acct=\"ubuntu\" exe=\"/usr/sbin/sshd\" terminal=ssh res=success'")))
	assert.NoError(t, m.Flush())

	assert.NotContains(t, w.String(), "cron")
	assert.Contains(t, w.String(), "\"sequence\":9")
}

func TestMarshallerFilters(t *testing.T) {
	w := &bytes.Buffer{}
	filters := []Filter{{Syscall: "49", MessageType: TypeSockaddr, Regex: regexp.MustCompile(`saddr=0A`)}}
	m := NewMarshaller(newJSONWriter(w), Options{EventMin: 1300, EventMax: 1399}, filters, nil, discard)

	// Matching group is dropped
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSyscall, "audit(1:1): syscall=49 success=yes")))
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSockaddr, "audit(1:1): saddr=0A00")))
	assert.NoError(t, m.Consume(newEOE("1")))
	assert.Empty(t, w.String())

	// Same syscall, different address, is kept
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSyscall, "audit(1:2): syscall=49 success=yes")))
	assert.NoError(t, m.Consume(newNetlinkMessage(TypeSockaddr, "audit(1:2): saddr=0200")))
	assert.NoError(t, m.Consume(newEOE("2")))
	assert.Contains(t, w.String(), "\"sequence\":2")
}

type recordingParser struct{ seen []uint16 }

func (p *recordingParser) Parse(am *Message) { p.seen = append(p.seen, am.Type) }

func TestMarshallerRunsExtraParsers(t *testing.T) {
	p := &recordingParser{}
	m := NewMarshaller(newJSONWriter(io.Discard), Options{EventMin: 1300, EventMax: 1399}, nil, []ExtraParser{p}, discard)

	assert.NoError(t, m.Consume(newNetlinkMessage(1300, "audit(1:1): a")))
	assert.NoError(t, m.Consume(newNetlinkMessage(1302, "audit(1:1): b")))
	assert.NoError(t, m.Consume(newEOE("1")))
	assert.Equal(t, []uint16{1300, 1302}, p.seen)
}

func TestMarshallerDetectMissing(t *testing.T) {
	elb := &bytes.Buffer{}
	log := textLogger(elb)
	m := NewMarshaller(newJSONWriter(io.Discard), Options{EventMin: 1300, EventMax: 1399, TrackMessages: true, LogOutOfOrder: true, MaxOutOfOrder: 2}, nil, nil, log)

	for _, seq := range []string{"1", "3", "2"} {
		assert.NoError(t, m.Consume(newEOE(seq)))
	}

	assert.Equal(t, "level=WARN msg=\"sequence arrived out of order\" seq=2 lag=1 worst_lag=1\n", elb.String())

	elb.Reset()
	for _, seq := range []string{"5", "6", "7", "8"} {
		assert.NoError(t, m.Consume(newEOE(seq)))
	}

	assert.Equal(t, "level=WARN msg=\"likely missed sequence\" seq=4 current=7 worst_lag=1\n", elb.String())
}

func BenchmarkMultiPacketMessage(b *testing.B) {
	m := NewMarshaller(newJSONWriter(io.Discard), Options{EventMin: 1300, EventMax: 1399, MaxOutOfOrder: 1}, nil, nil, discard)

	data := make([][]byte, 6)

	// &{1300,,arch=c000003e,syscall=59,success=yes,exit=0,a0=cc4e68,a1=d10bc8,a2=c69808,a3=7fff2a700900,items=2,ppid=11552,pid=11623,auid=1000,uid=1000,gid=1000,euid=1000,suid=1000,fsuid=1000,egid=1000,sgid=1000,fsgid=1000,tty=pts0,ses=35,comm="ls",exe="/bin/ls",key=(null),1222763,1459376866.885}
	data[0] = []byte{34, 1, 0, 0, 20, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 97, 114, 99, 104, 61, 99, 48, 48, 48, 48, 48, 51, 101, 32, 115, 121, 115, 99, 97, 108, 108, 61, 53, 57, 32, 115, 117, 99, 99, 101, 115, 115, 61, 121, 101, 115, 32, 101, 120, 105, 116, 61, 48, 32, 97, 48, 61, 99, 99, 52, 101, 54, 56, 32, 97, 49, 61, 100, 49, 48, 98, 99, 56, 32, 97, 50, 61, 99, 54, 57, 56, 48, 56, 32, 97, 51, 61, 55, 102, 102, 102, 50, 97, 55, 48, 48, 57, 48, 48, 32, 105, 116, 101, 109, 115, 61, 50, 32, 112, 112, 105, 100, 61, 49, 49, 53, 53, 50, 32, 112, 105, 100, 61, 49, 49, 54, 50, 51, 32, 97, 117, 105, 100, 61, 49, 48, 48, 48, 32, 117, 105, 100, 61, 49, 48, 48, 48, 32, 103, 105, 100, 61, 49, 48, 48, 48, 32, 101, 117, 105, 100, 61, 49, 48, 48, 48, 32, 115, 117, 105, 100, 61, 49, 48, 48, 48, 32, 102, 115, 117, 105, 100, 61, 49, 48, 48, 48, 32, 101, 103, 105, 100, 61, 49, 48, 48, 48, 32, 115, 103, 105, 100, 61, 49, 48, 48, 48, 32, 102, 115, 103, 105, 100, 61, 49, 48, 48, 48, 32, 116, 116, 121, 61, 112, 116, 115, 48, 32, 115, 101, 115, 61, 51, 53, 32, 99, 111, 109, 109, 61, 34, 108, 115, 34, 32, 101, 120, 101, 61, 34, 47, 98, 105, 110, 47, 108, 115, 34, 32, 107, 101, 121, 61, 40, 110, 117, 108, 108, 41}

	// &{1309,,argc=3,a0="ls",a1="--color=auto",a2="-alF",1222763,1459376866.885}
	data[1] = []byte{73, 0, 0, 0, 29, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 97, 114, 103, 99, 61, 51, 32, 97, 48, 61, 34, 108, 115, 34, 32, 97, 49, 61, 34, 45, 45, 99, 111, 108, 111, 114, 61, 97, 117, 116, 111, 34, 32, 97, 50, 61, 34, 45, 97, 108, 70, 34}

	// &{1307,,,cwd="/home/ubuntu/src/slack-github.com/rhuber/go-audit-new",1222763,1459376866.885}
	data[2] = []byte{91, 0, 0, 0, 27, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 32, 99, 119, 100, 61, 34, 47, 104, 111, 109, 101, 47, 117, 98, 117, 110, 116, 117, 47, 115, 114, 99, 47, 115, 108, 97, 99, 107, 45, 103, 105, 116, 104, 117, 98, 46, 99, 111, 109, 47, 114, 104, 117, 98, 101, 114, 47, 103, 111, 45, 97, 117, 100, 105, 116, 45, 110, 101, 119, 34}

	// &{1302,,item=0,name="/bin/ls",inode=262316,dev=ca:01,mode=0100755,ouid=0,ogid=0,rdev=00:00,nametype=NORMAL,1222763,1459376866.885}
	data[3] = []byte{129, 0, 0, 0, 22, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 105, 116, 101, 109, 61, 48, 32, 110, 97, 109, 101, 61, 34, 47, 98, 105, 110, 47, 108, 115, 34, 32, 105, 110, 111, 100, 101, 61, 50, 54, 50, 51, 49, 54, 32, 100, 101, 118, 61, 99, 97, 58, 48, 49, 32, 109, 111, 100, 101, 61, 48, 49, 48, 48, 55, 53, 53, 32, 111, 117, 105, 100, 61, 48, 32, 111, 103, 105, 100, 61, 48, 32, 114, 100, 101, 118, 61, 48, 48, 58, 48, 48, 32, 110, 97, 109, 101, 116, 121, 112, 101, 61, 78, 79, 82, 77, 65, 76}

	// &{1302,,item=1,name="/lib64/ld-linux-x86-64.so.2",inode=396037,dev=ca:01,mode=0100755,ouid=0,ogid=0,rdev=00:00,nametype=NORMAL,1222763,1459376866.885}
	data[4] = []byte{149, 0, 0, 0, 22, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32, 105, 116, 101, 109, 61, 49, 32, 110, 97, 109, 101, 61, 34, 47, 108, 105, 98, 54, 52, 47, 108, 100, 45, 108, 105, 110, 117, 120, 45, 120, 56, 54, 45, 54, 52, 46, 115, 111, 46, 50, 34, 32, 105, 110, 111, 100, 101, 61, 51, 57, 54, 48, 51, 55, 32, 100, 101, 118, 61, 99, 97, 58, 48, 49, 32, 109, 111, 100, 101, 61, 48, 49, 48, 48, 55, 53, 53, 32, 111, 117, 105, 100, 61, 48, 32, 111, 103, 105, 100, 61, 48, 32, 114, 100, 101, 118, 61, 48, 48, 58, 48, 48, 32, 110, 97, 109, 101, 116, 121, 112, 101, 61, 78, 79, 82, 77, 65, 76}

	// &{1320,,,1222763,1459376866.885}
	data[5] = []byte{31, 0, 0, 0, 40, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 117, 100, 105, 116, 40, 49, 52, 53, 57, 51, 55, 54, 56, 54, 54, 46, 56, 56, 53, 58, 49, 50, 50, 50, 55, 54, 51, 41, 58, 32}

	le := binary.LittleEndian
	for b.Loop() {
		for _, d := range data {
			msg := &syscall.NetlinkMessage{
				Header: syscall.NlMsghdr{
					Len:   le.Uint32(d[0:4]),
					Type:  le.Uint16(d[4:6]),
					Flags: le.Uint16(d[6:8]),
					Seq:   le.Uint32(d[8:12]),
					Pid:   le.Uint32(d[12:16]),
				},
				Data: d[syscall.SizeofNlMsghdr:],
			}
			_ = m.Consume(msg)
		}
	}
}

var discard = slog.New(slog.DiscardHandler)

// textLogger writes text log lines without timestamps, for assertions.
func textLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}

			return a
		},
	}))
}
