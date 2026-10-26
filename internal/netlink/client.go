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

	auditSet          = 1001            // AUDIT_SET
	auditStatusPid    = 4               // AUDIT_STATUS_PID
	keepAliveInterval = 5 * time.Second // How often the audit daemon registration is renewed
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

// Client is a NETLINK_AUDIT socket.
type Client struct {
	fd      int
	address syscall.Sockaddr
	seq     atomic.Uint32
	buf     []byte
	log     *slog.Logger
	stop    context.CancelFunc
}

// New opens the audit socket, registers this process as the audit daemon and
// keeps that registration alive until ctx is done. recvSize sets the socket
// receive buffer when greater than zero. recvTimeout bounds each Receive call
// when greater than zero.
func New(ctx context.Context, recvSize int, recvTimeout time.Duration, log *slog.Logger) (*Client, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return nil, fmt.Errorf("could not create a socket: %w", err)
	}

	n := &Client{
		fd:      fd,
		address: &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK},
		buf:     make([]byte, MaxAuditMessageLength),
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

	ctx, n.stop = context.WithCancel(ctx)
	go n.keepAlive(ctx)

	return n, nil
}

// Close stops the keepalive and closes the socket.
func (n *Client) Close() error {
	if n.stop != nil {
		n.stop()
	}

	return syscall.Close(n.fd)
}

// keepAlive renews the registration until ctx is done, so this process stays
// the audit daemon if another one, such as auditd, claims the role.
func (n *Client) keepAlive(ctx context.Context) {
	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()

	for {
		n.KeepConnection()

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Send writes a packet and payload to the socket without waiting for a response.
// It sets the Seq and Len fields of np.
func (n *Client) Send(np *Packet, a *AuditStatusPayload) error {
	np.Seq = n.seq.Add(1)
	np.Len = uint32(syscall.SizeofNlMsghdr + binary.Size(a))

	buf := bytes.NewBuffer(make([]byte, 0, np.Len))
	if err := binary.Write(buf, byteOrder, np); err != nil {
		return err
	}

	if err := binary.Write(buf, byteOrder, a); err != nil {
		return err
	}

	return syscall.Sendto(n.fd, buf.Bytes(), 0, n.address)
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

// KeepConnection (re)registers this process as the audit daemon.
func (n *Client) KeepConnection() {
	pid := uint32(syscall.Getpid())

	payload := &AuditStatusPayload{
		Mask:    auditStatusPid,
		Enabled: 1,
		Pid:     pid,
	}

	packet := &Packet{
		Type:  auditSet,
		Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		Pid:   pid,
	}

	if err := n.Send(packet, payload); err != nil {
		n.log.Error("failed to keep the audit connection", "err", err)
	}
}
