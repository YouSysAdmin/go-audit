package netlink

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegister(t *testing.T) {
	n := newUnixClient(t, discard)

	require.NoError(t, n.Register())
	msg, err := n.Receive()
	require.NoError(t, err)

	expectedData := make([]byte, 40)
	binary.LittleEndian.PutUint32(expectedData[0:4], 4)
	binary.LittleEndian.PutUint32(expectedData[4:8], 1)
	binary.LittleEndian.PutUint32(expectedData[12:16], uint32(os.Getpid()))

	assert.Equal(t, uint16(1001), msg.Header.Type)
	assert.Equal(t, uint16(5), msg.Header.Flags)
	assert.Equal(t, uint32(1), msg.Header.Seq)
	assert.Equal(t, uint32(56), msg.Header.Len)
	assert.Equal(t, expectedData, msg.Data[:40])

	_ = syscall.Close(n.fd)
	assert.EqualError(t, n.Register(), "bad file descriptor")
}

// statusReply builds a netlink message as the kernel sends it.
func statusReply(typ uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, syscall.SizeofNlMsghdr+len(payload))
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:6], typ)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	copy(b[syscall.SizeofNlMsghdr:], payload)

	return b
}

func statusPayload(fields ...uint32) []byte {
	b := make([]byte, 4*len(fields))
	for i, v := range fields {
		binary.NativeEndian.PutUint32(b[i*4:], v)
	}

	return b
}

func TestParseStatusReply(t *testing.T) {
	// mask enabled failure pid rate_limit backlog_limit lost backlog version backlog_wait_time
	full := statusPayload(0, 1, 1, 4242, 0, 8192, 17, 3, 7, 60000)

	st, done, err := parseStatusReply(statusReply(auditGet, 9, full), 9)
	require.NoError(t, err)
	assert.True(t, done)
	assert.Equal(t, &Status{Enabled: 1, Failure: 1, PID: 4242, BacklogLimit: 8192, Lost: 17, Backlog: 3}, st)

	// Older kernels reply with fewer fields
	st, done, err = parseStatusReply(statusReply(auditGet, 9, statusPayload(0, 1, 1, 4242)), 9)
	require.NoError(t, err)
	assert.True(t, done)
	assert.Equal(t, &Status{Enabled: 1, Failure: 1, PID: 4242}, st)

	// A reply to an earlier request is skipped
	_, done, err = parseStatusReply(statusReply(auditGet, 8, full), 9)
	assert.NoError(t, err)
	assert.False(t, done)

	// An ACK is skipped, the status follows
	_, done, err = parseStatusReply(statusReply(syscall.NLMSG_ERROR, 9, statusPayload(0)), 9)
	assert.NoError(t, err)
	assert.False(t, done)

	// A kernel error ends the request
	minusOne := int32(-1)
	eperm := uint32(minusOne)
	_, done, err = parseStatusReply(statusReply(syscall.NLMSG_ERROR, 9, statusPayload(eperm)), 9)
	assert.True(t, done)
	assert.ErrorIs(t, err, syscall.EPERM)

	_, done, _ = parseStatusReply([]byte{1, 2, 3}, 9)
	assert.False(t, done)
}

func TestCheck(t *testing.T) {
	elb := &bytes.Buffer{}
	n := newUnixClient(t, textLogger(elb))
	n.lastLost = 10

	// Still registered, nothing lost: no AUDIT_SET and no log line
	n.check(&Status{PID: n.pid, Lost: 10})
	assert.Empty(t, elb.String())
	assertNothingSent(t, n)

	// Registration lost: AUDIT_SET is sent again
	n.check(&Status{PID: 0, Lost: 10})
	assert.Equal(t, "level=WARN msg=\"audit daemon registration lost, registering again\" registered_pid=0\n", elb.String())
	msg, err := n.Receive()
	require.NoError(t, err)
	assert.Equal(t, uint16(auditSet), msg.Header.Type)

	// Dropped records are reported once, as the difference
	elb.Reset()
	n.check(&Status{PID: n.pid, Lost: 15, Backlog: 2, BacklogLimit: 64})
	n.check(&Status{PID: n.pid, Lost: 15})
	assert.Equal(t, "level=WARN msg=\"kernel dropped audit records\" lost=5 lost_total=15 backlog=2 backlog_limit=64\n", elb.String())
}

func assertNothingSent(t *testing.T, n *Client) {
	t.Helper()

	tv := syscall.NsecToTimeval((10 * time.Millisecond).Nanoseconds())
	require.NoError(t, syscall.SetsockoptTimeval(n.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv))

	_, err := n.Receive()
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestSendReceive(t *testing.T) {
	n := newUnixClient(t, discard)

	payload := &AuditStatusPayload{Mask: 4, Enabled: 1, Pid: 1006}
	packet := &Packet{
		Type:  1001,
		Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		Pid:   1006,
	}

	msg := sendReceive(t, n, packet, payload)
	assert.Equal(t, uint32(1006), msg.Header.Pid)
	assert.Equal(t, packet.Type, msg.Header.Type)
	assert.Equal(t, packet.Flags, msg.Header.Flags)
	assert.Equal(t, uint32(1), msg.Header.Seq)
	assert.Equal(t, uint32(56), msg.Header.Len)
	assert.Equal(t, []byte{4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 238, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, msg.Data[:40])

	// Sequence numbers increment on our side
	msg = sendReceive(t, n, packet, payload)
	assert.Equal(t, uint32(2), msg.Header.Seq)

	// 0 length packets are an error
	require.NoError(t, syscall.Sendto(n.fd, []byte{}, 0, n.address))
	_, err := n.Receive()
	assert.EqualError(t, err, "got a 0 length packet")

	// Packets shorter than a header are an error, not a panic
	require.NoError(t, syscall.Sendto(n.fd, []byte{1, 2, 3}, 0, n.address))
	_, err = n.Receive()
	assert.EqualError(t, err, "got a short packet of 3 bytes")

	// sendto errors come back
	_ = syscall.Close(n.fd)
	assert.EqualError(t, n.Send(packet, payload), "bad file descriptor")

	// recvfrom errors come back
	devnull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	t.Cleanup(func() { _ = devnull.Close() })

	n.fd = int(devnull.Fd())
	_, err = n.Receive()
	assert.EqualError(t, err, "socket operation on non-socket")
}

func TestReceiveTimeout(t *testing.T) {
	n := newUnixClient(t, discard)

	tv := syscall.NsecToTimeval((10 * time.Millisecond).Nanoseconds())
	require.NoError(t, syscall.SetsockoptTimeval(n.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv))

	_, err := n.Receive()
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestNew(t *testing.T) {
	lb := &lockedBuffer{}

	n, err := New(t.Context(), 1024, time.Second, textLogger(lb))
	if err != nil {
		// Creating an audit socket needs CAP_AUDIT_CONTROL in some environments
		t.Skipf("netlink audit socket unavailable: %v", err)
	}

	t.Cleanup(func() { _ = n.Close() })

	assert.GreaterOrEqual(t, n.fd, 0)
	assert.NotNil(t, n.address)
	assert.LessOrEqual(t, len(n.buf), MaxAuditMessageLength)
	assert.Contains(t, lb.String(), "msg=\"socket receive buffer\" size=")
}

// lockedBuffer is a bytes.Buffer safe for the keepalive goroutine to log into.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// newUnixClient returns a client bound to a unix socket that sends to itself.
func newUnixClient(t *testing.T, log *slog.Logger) *Client {
	t.Helper()

	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_RAW, 0)
	require.NoError(t, err)

	n := &Client{
		fd:      fd,
		ctl:     -1,
		address: &syscall.SockaddrUnix{Name: filepath.Join(t.TempDir(), "go-audit.test.sock")},
		buf:     make([]byte, MaxAuditMessageLength),
		pid:     uint32(os.Getpid()),
		log:     log,
	}

	if err := syscall.Bind(fd, n.address); err != nil {
		_ = syscall.Close(fd)
		t.Fatal("could not bind socket:", err)
	}

	t.Cleanup(func() { _ = syscall.Close(n.fd) })

	return n
}

func sendReceive(t *testing.T, n *Client, packet *Packet, payload *AuditStatusPayload) *syscall.NetlinkMessage {
	t.Helper()

	require.NoError(t, n.Send(packet, payload))

	msg, err := n.Receive()
	require.NoError(t, err)

	return msg
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
