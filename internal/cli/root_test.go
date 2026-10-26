package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yousysadmin/go-audit/internal/audit"
	"github.com/yousysadmin/go-audit/internal/event"
	"github.com/yousysadmin/go-audit/internal/netlink"
	"github.com/yousysadmin/go-audit/internal/output"
	"github.com/yousysadmin/go-audit/pkg"
)

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()

	out := &bytes.Buffer{}
	root := NewRoot()
	root.SetArgs(args)
	root.SetOut(out)
	root.SetErr(out)

	err := root.Execute()

	return out.String(), err
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--nope"},
		{"stray"},
		{"version", "stray"},
	} {
		_, err := execute(t, args...)
		require.Error(t, err, args)
		assert.Equal(t, 2, ExitCode(err), "%v: %v", args, err)
	}
}

func TestExitCodeForOtherErrors(t *testing.T) {
	_, err := execute(t, "--config", "/does/not/exist.yaml")
	require.Error(t, err)
	assert.Equal(t, 1, ExitCode(err))
	assert.Equal(t, 0, ExitCode(nil))
}

func TestVersion(t *testing.T) {
	out, err := execute(t, "version")
	require.NoError(t, err)
	assert.Equal(t, pkg.AppName+" "+pkg.Version+"\n", out)

	out, err = execute(t, "--version")
	require.NoError(t, err)
	assert.Equal(t, pkg.AppName+" version "+pkg.Version+"\n", out)
}

type fakeReceiver struct {
	msgs   []*syscall.NetlinkMessage
	errs   []error
	cancel context.CancelFunc
}

func (f *fakeReceiver) Receive() (*syscall.NetlinkMessage, error) {
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]

		return nil, err
	}

	if len(f.msgs) == 0 {
		f.cancel()

		return nil, netlink.ErrTimeout
	}

	msg := f.msgs[0]
	f.msgs = f.msgs[1:]

	return msg, nil
}

type groupRecorder struct{ seqs []int }

func (g *groupRecorder) Write(msg *audit.MessageGroup) error {
	g.seqs = append(g.seqs, msg.Seq)

	return nil
}

func TestConsumeFlushesOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	elb := &bytes.Buffer{}
	log := textLogger(elb)

	rec := &groupRecorder{}
	m := audit.NewMarshaller(rec, audit.Options{EventMin: 1300, EventMax: 1399}, nil, nil, log)
	r := &fakeReceiver{
		errs: []error{errors.New("transient")},
		msgs: []*syscall.NetlinkMessage{
			{Header: syscall.NlMsghdr{Type: 1300}, Data: []byte("audit(1:7): pending")},
		},
		cancel: cancel,
	}

	require.NoError(t, consume(ctx, r, m, log))
	assert.Equal(t, []int{7}, rec.seqs, "pending groups should be written on shutdown")
	assert.Contains(t, elb.String(), "level=ERROR msg=\"failed to receive message\" err=transient\n")
}

func TestConsumeStopsOnClosedSocket(t *testing.T) {
	m := audit.NewMarshaller(&groupRecorder{}, audit.Options{EventMin: 1300, EventMax: 1399}, nil, nil, discard)
	r := &fakeReceiver{errs: []error{syscall.EBADF}}

	assert.ErrorIs(t, consume(t.Context(), r, m, discard), syscall.EBADF)
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

func TestPipelineWritesEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	buf := &bytes.Buffer{}
	b := event.NewBuilder(event.Options{Host: "web-1", Tags: map[string]string{"env": "prod"}})
	w := event.NewWriter(b, output.NewWriter(buf, 1, discard))
	m := audit.NewMarshaller(w, audit.Options{EventMin: 1300, EventMax: 1399}, nil, nil, discard)

	nl := func(typ uint16, data string) *syscall.NetlinkMessage {
		return &syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: typ}, Data: []byte(data)}
	}

	r := &fakeReceiver{
		msgs: []*syscall.NetlinkMessage{
			nl(1300, `audit(1459376866.885:42): arch=c000003e syscall=59 success=yes exit=0 pid=7 uid=0 comm="ls" exe="/bin/ls" key="cmds"`),
			nl(1309, `audit(1459376866.885:42): argc=2 a0="ls" a1="-l"`),
			nl(1320, `audit(1459376866.885:42): `),
		},
		cancel: cancel,
	}

	require.NoError(t, consume(ctx, r, m, discard))

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "2016-03-30T22:27:46.885Z", got["time"])
	assert.Equal(t, "web-1", got["host"])
	assert.Equal(t, map[string]any{"env": "prod"}, got["tags"])
	assert.Equal(t, "cmds", got["key"])
	assert.Equal(t, "execve", got["syscall"].(map[string]any)["name"])
	assert.Equal(t, []any{"ls", "-l"}, got["process"].(map[string]any)["args"])
	assert.Len(t, got["records"], 2)
}
