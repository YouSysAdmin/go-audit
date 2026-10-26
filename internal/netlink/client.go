// Package netlink talks to the kernel audit subsystem over a NETLINK_AUDIT socket.
package netlink

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// MaxAuditMessageLength is MAX_AUDIT_MESSAGE_LENGTH, the largest record the kernel sends.
	MaxAuditMessageLength = 8970

	auditGet          = 1000            // AUDIT_GET
	auditSet          = 1001            // AUDIT_SET
	auditStatusPid    = 4               // AUDIT_STATUS_PID
	keepAliveInterval = 5 * time.Second // How often the registration and the counters are checked
	statusTimeout     = time.Second     // How long to wait for an AUDIT_GET reply
)

// ErrTimeout is returned by Receive when no message arrived within the receive timeout.
var ErrTimeout = errors.New("netlink receive timeout")

// byteOrder is the byte order of netlink headers, which is the host order.
var byteOrder = binary.NativeEndian

// AuditStatusPayload mirrors struct audit_status.
type AuditStatusPayload struct {
	Mask            uint32
	Enabled         uint32
	Failure         uint32
	Pid             uint32
	RateLimit       uint32
	BacklogLimit    uint32
	Lost            uint32
	Backlog         uint32
	Version         uint32
	BacklogWaitTime uint32
}

// Packet is a netlink message header.
type Packet syscall.NlMsghdr

// Status is the kernel audit state, the reply to AUDIT_GET.
type Status struct {
	Enabled      uint32
	Failure      uint32
	PID          uint32 // Registered audit daemon, 0 when none
	RateLimit    uint32
	BacklogLimit uint32
	Lost         uint32 // Records the kernel dropped since boot
	Backlog      uint32 // Records waiting in the kernel queue
}

// Client is a NETLINK_AUDIT socket that receives events, plus a second socket
// for status requests so their replies do not mix with the events.
type Client struct {
	fd       int
	ctl      int
	address  syscall.Sockaddr
	seq      atomic.Uint32
	buf      []byte
	ctlBuf   []byte
	pid      uint32
	lastLost uint32
	log      *slog.Logger
	stop     context.CancelFunc
}

// New opens the audit sockets, registers this process as the audit daemon and
// checks the registration until ctx is done. It fails when another process,
// such as auditd, already is the audit daemon. recvSize sets the socket
// receive buffer when greater than zero. recvTimeout bounds each Receive call
// when greater than zero.
func New(ctx context.Context, recvSize int, recvTimeout time.Duration, log *slog.Logger) (*Client, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return nil, fmt.Errorf("could not create a socket: %w", err)
	}

	n := &Client{
		fd:      fd,
		ctl:     -1,
		address: &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK},
		buf:     make([]byte, MaxAuditMessageLength),
		ctlBuf:  make([]byte, MaxAuditMessageLength),
		pid:     uint32(syscall.Getpid()),
		log:     log,
	}

	if err = syscall.Bind(fd, n.address); err != nil {
		_ = syscall.Close(fd)

		return nil, fmt.Errorf("could not bind to netlink socket: %w", err)
	}

	if recvSize > 0 {
		if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, recvSize); err != nil {
			log.Warn("failed to set socket receive buffer size", "size", recvSize, "err", err)
		}
	}

	if v, err := syscall.GetsockoptInt(n.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil {
		log.Info("socket receive buffer", "size", v)
	}

	if recvTimeout > 0 {
		tv := syscall.NsecToTimeval(recvTimeout.Nanoseconds())
		if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			_ = syscall.Close(fd)

			return nil, fmt.Errorf("could not set receive timeout: %w", err)
		}
	}

	if n.ctl, err = openControl(); err != nil {
		_ = syscall.Close(fd)

		return nil, err
	}

	if err := n.Register(); err != nil {
		_ = n.Close()

		return nil, fmt.Errorf("could not register as the audit daemon: %w", err)
	}

	st, err := n.Status()
	if err != nil {
		_ = n.Close()

		return nil, fmt.Errorf("could not read the audit status: %w", err)
	}

	if st.PID != n.pid {
		_ = n.Close()

		return nil, fmt.Errorf("process %d is already the audit daemon, stop it (usually auditd) first", st.PID)
	}

	n.lastLost = st.Lost
	log.Info("registered as the audit daemon",
		"enabled", st.Enabled, "backlog_limit", st.BacklogLimit, "lost", st.Lost, "backlog", st.Backlog)

	ctx, n.stop = context.WithCancel(ctx)
	go n.keepAlive(ctx)

	return n, nil
}

// openControl opens the socket used for AUDIT_GET.
func openControl() (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return -1, fmt.Errorf("could not create the control socket: %w", err)
	}

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		_ = syscall.Close(fd)

		return -1, fmt.Errorf("could not bind the control socket: %w", err)
	}

	tv := syscall.NsecToTimeval(statusTimeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		_ = syscall.Close(fd)

		return -1, fmt.Errorf("could not set the control socket timeout: %w", err)
	}

	return fd, nil
}

// Close stops the keepalive and closes the sockets.
func (n *Client) Close() error {
	if n.stop != nil {
		n.stop()
	}

	if n.ctl >= 0 {
		_ = syscall.Close(n.ctl)
	}

	return syscall.Close(n.fd)
}

// keepAlive checks the kernel status until ctx is done. AUDIT_SET is only sent
// again when the registration was lost, the kernel logs every AUDIT_SET as a
// CONFIG_CHANGE record, refused ones included.
func (n *Client) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		st, err := n.Status()
		if err != nil {
			n.log.Warn("failed to read the audit status", "err", err)

			continue
		}

		n.check(st)
	}
}

// check registers again when another pid holds the registration, or none does,
// and reports records the kernel dropped since the last check.
func (n *Client) check(st *Status) {
	if st.PID != n.pid {
		n.log.Warn("audit daemon registration lost, registering again", "registered_pid", st.PID)

		if err := n.Register(); err != nil {
			n.log.Error("failed to register as the audit daemon", "err", err)
		}
	}

	if st.Lost > n.lastLost {
		n.log.Warn("kernel dropped audit records",
			"lost", st.Lost-n.lastLost, "lost_total", st.Lost, "backlog", st.Backlog, "backlog_limit", st.BacklogLimit)
	}

	n.lastLost = st.Lost
}

// Send writes a packet and an optional payload to the event socket without
// waiting for a response. It sets the Seq and Len fields of np.
func (n *Client) Send(np *Packet, payload any) error {
	return n.send(n.fd, np, payload)
}

func (n *Client) send(fd int, np *Packet, payload any) error {
	np.Seq = n.seq.Add(1)
	np.Len = uint32(syscall.SizeofNlMsghdr)
	if payload != nil {
		np.Len += uint32(binary.Size(payload))
	}

	buf := bytes.NewBuffer(make([]byte, 0, np.Len))
	if err := binary.Write(buf, byteOrder, np); err != nil {
		return err
	}

	if payload != nil {
		if err := binary.Write(buf, byteOrder, payload); err != nil {
			return err
		}
	}

	return syscall.Sendto(fd, buf.Bytes(), 0, n.address)
}

// Status asks the kernel for its audit state on the control socket.
func (n *Client) Status() (*Status, error) {
	req := &Packet{Type: auditGet, Flags: syscall.NLM_F_REQUEST, Pid: n.pid}
	if err := n.send(n.ctl, req, nil); err != nil {
		return nil, err
	}

	for {
		nlen, _, err := syscall.Recvfrom(n.ctl, n.ctlBuf, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}

		if errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("no reply to AUDIT_GET")
		}

		if err != nil {
			return nil, err
		}

		st, done, err := parseStatusReply(n.ctlBuf[:nlen], req.Seq)
		if done {
			return st, err
		}
	}
}

// parseStatusReply reads one reply to the AUDIT_GET with sequence seq. done is
// false for a message that belongs to an earlier request.
func parseStatusReply(b []byte, seq uint32) (st *Status, done bool, err error) {
	if len(b) < syscall.SizeofNlMsghdr {
		return nil, false, nil
	}

	if byteOrder.Uint32(b[8:12]) != seq {
		return nil, false, nil
	}

	data := b[syscall.SizeofNlMsghdr:]

	switch byteOrder.Uint16(b[4:6]) {
	case syscall.NLMSG_ERROR:
		if len(data) < 4 {
			return nil, true, errors.New("short netlink error reply")
		}

		if errno := int32(byteOrder.Uint32(data[:4])); errno != 0 {
			return nil, true, syscall.Errno(-errno)
		}

		// An ACK, the status follows
		return nil, false, nil
	case auditGet:
		// Older kernels send a shorter struct audit_status, missing fields stay 0
		var raw AuditStatusPayload
		full := make([]byte, binary.Size(raw))
		copy(full, data)

		if err := binary.Read(bytes.NewReader(full), byteOrder, &raw); err != nil {
			return nil, true, err
		}

		return &Status{
			Enabled:      raw.Enabled,
			Failure:      raw.Failure,
			PID:          raw.Pid,
			RateLimit:    raw.RateLimit,
			BacklogLimit: raw.BacklogLimit,
			Lost:         raw.Lost,
			Backlog:      raw.Backlog,
		}, true, nil
	default:
		return nil, false, nil
	}
}

// Receive reads one packet. The returned Data aliases an internal buffer and is
// only valid until the next call. It returns ErrTimeout when the receive
// timeout expires.
func (n *Client) Receive() (*syscall.NetlinkMessage, error) {
	var (
		nlen int
		err  error
	)

	// A signal interrupts the blocking call, retry it
	for {
		nlen, _, err = syscall.Recvfrom(n.fd, n.buf, 0)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}

	// SO_RCVTIMEO expired
	if errors.Is(err, syscall.EAGAIN) {
		return nil, ErrTimeout
	}

	if err != nil {
		return nil, err
	}

	if nlen < 1 {
		return nil, errors.New("got a 0 length packet")
	}

	if nlen < syscall.SizeofNlMsghdr {
		return nil, fmt.Errorf("got a short packet of %d bytes", nlen)
	}

	msg := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   byteOrder.Uint32(n.buf[0:4]),
			Type:  byteOrder.Uint16(n.buf[4:6]),
			Flags: byteOrder.Uint16(n.buf[6:8]),
			Seq:   byteOrder.Uint32(n.buf[8:12]),
			Pid:   byteOrder.Uint32(n.buf[12:16]),
		},
		Data: n.buf[syscall.SizeofNlMsghdr:nlen],
	}

	return msg, nil
}

// Register makes this process the audit daemon. It is sent on the event socket
// because the kernel delivers records to the socket that registered.
func (n *Client) Register() error {
	payload := &AuditStatusPayload{
		Mask:    auditStatusPid,
		Enabled: 1,
		Pid:     n.pid,
	}

	packet := &Packet{
		Type:  auditSet,
		Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		Pid:   n.pid,
	}

	return n.Send(packet, payload)
}
