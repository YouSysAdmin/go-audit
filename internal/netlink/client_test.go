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

func TestKeepConnection(t *testing.T) {
	elb := &bytes.Buffer{}
	n := newUnixClient(t, textLogger(elb))

	n.KeepConnection()
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
	assert.Empty(t, elb.String())

	// Send errors are logged
	_ = syscall.Close(n.fd)
	n.KeepConnection()
	assert.Equal(t, "level=ERROR msg=\"failed to keep the audit connection\" err=\"bad file descriptor\"\n", elb.String())
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
		address: &syscall.SockaddrUnix{Name: filepath.Join(t.TempDir(), "go-audit.test.sock")},
		buf:     make([]byte, MaxAuditMessageLength),
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
