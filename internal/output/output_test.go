package output

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"log/syslog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yousysadmin/go-audit/internal/config"
)

// currentOwner returns the user and group names of the test process.
func currentOwner(t *testing.T) (string, string) {
	t.Helper()

	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	require.NoError(t, err)

	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	require.NoError(t, err)

	return u.Username, g.Name
}

func TestNewFile(t *testing.T) {
	log := discard
	path := filepath.Join(t.TempDir(), "go-audit.test.log")
	uname, gname := currentOwner(t)

	_, err := NewFile(config.File{Attempts: 0}, log)
	assert.EqualError(t, err, "output attempts for file must be at least 1, 0 provided")

	_, err = NewFile(config.File{Attempts: 1, Path: path}, log)
	assert.EqualError(t, err, "output file mode should be greater than 0000")

	_, err = NewFile(config.File{Attempts: 1, Path: path, Mode: 0o644}, log)
	assert.EqualError(t, err, "could not find uid for user : user: unknown user ")

	_, err = NewFile(config.File{Attempts: 1, Path: path, Mode: 0o644, User: uname}, log)
	assert.EqualError(t, err, "could not find gid for group : group: unknown group ")

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "a failed owner lookup should not create the file")

	_, err = NewFile(config.File{Attempts: 1, Path: "/do/not/exist/please", Mode: 0o644, User: uname, Group: gname}, log)
	assert.EqualError(t, err, "failed to open output file: open /do/not/exist/please: no such file or directory")

	if os.Getuid() != 0 {
		_, err = NewFile(config.File{Attempts: 1, Path: path, Mode: 0o644, User: "root", Group: "root"}, log)
		assert.EqualError(t, err, "could not chown output file: chown "+path+": operation not permitted")
	}

	w, err := NewFile(config.File{Attempts: 1, Path: path, Mode: 0o600, User: uname, Group: gname}, log)
	require.NoError(t, err)
	assert.IsType(t, &os.File{}, w.Underlying())

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestNewSyslog(t *testing.T) {
	log := discard

	_, err := NewSyslog(config.Syslog{Attempts: 0}, log)
	assert.EqualError(t, err, "output attempts for syslog must be at least 1, 0 provided")

	_, err = NewSyslog(config.Syslog{Attempts: 1, Priority: -1}, log)
	assert.EqualError(t, err, "failed to open syslog writer: log/syslog: invalid priority")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	w, err := NewSyslog(config.Syslog{Attempts: 1, Network: "tcp", Address: l.Addr().String()}, log)
	require.NoError(t, err)
	assert.IsType(t, &syslog.Writer{}, w.Underlying())
}

func TestNewStdout(t *testing.T) {
	log := discard

	_, err := NewStdout(config.Stdout{Attempts: 0}, log)
	assert.EqualError(t, err, "output attempts for stdout must be at least 1, 0 provided")

	w, err := NewStdout(config.Stdout{Attempts: 1}, log)
	require.NoError(t, err)
	assert.Equal(t, os.Stdout, w.Underlying())
}

func TestNew(t *testing.T) {
	log := discard
	uname, gname := currentOwner(t)
	path := filepath.Join(t.TempDir(), "go-audit.test.log")

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	fileCfg := config.File{Enabled: true, Attempts: 1, Path: path, Mode: 0o644, User: uname, Group: gname}
	syslogCfg := config.Syslog{Enabled: true, Attempts: 1, Network: "tcp", Address: l.Addr().String()}

	_, err = New(t.Context(), config.Output{}, log)
	assert.EqualError(t, err, "no outputs were configured")

	_, err = New(t.Context(), config.Output{Syslog: syslogCfg, File: fileCfg}, log)
	assert.EqualError(t, err, "only one output can be enabled at a time")

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "a rejected config should not touch the file")

	_, err = New(t.Context(), config.Output{Syslog: config.Syslog{Enabled: true}}, log)
	assert.EqualError(t, err, "output attempts for syslog must be at least 1, 0 provided")

	_, err = New(t.Context(), config.Output{File: config.File{Enabled: true}}, log)
	assert.EqualError(t, err, "output attempts for file must be at least 1, 0 provided")

	_, err = New(t.Context(), config.Output{Stdout: config.Stdout{Enabled: true}}, log)
	assert.EqualError(t, err, "output attempts for stdout must be at least 1, 0 provided")

	w, err := New(t.Context(), config.Output{Syslog: syslogCfg}, log)
	require.NoError(t, err)
	assert.IsType(t, &syslog.Writer{}, w.Underlying())

	w, err = New(t.Context(), config.Output{File: fileCfg}, log)
	require.NoError(t, err)
	assert.IsType(t, &os.File{}, w.Underlying())
}

func TestHandleRotation(t *testing.T) {
	log := discard
	uname, gname := currentOwner(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "go-audit.test.log")
	cfg := config.File{Enabled: true, Attempts: 1, Path: path, Mode: 0o644, User: uname, Group: gname}

	w, err := New(t.Context(), config.Output{File: cfg}, log)
	require.NoError(t, err)

	first := w.Underlying()
	require.NoError(t, os.Rename(path, filepath.Join(dir, "go-audit.test.log.rotated")))
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))

	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGUSR1))

	assert.Eventually(t, func() bool {
		_, err := os.Stat(path)

		return err == nil && w.Underlying() != first
	}, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, w.Write(map[string]int{"sequence": 7}))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "\"sequence\":7")
}

type flakyWriter struct {
	fails int
	buf   bytes.Buffer
}

func (f *flakyWriter) Write(p []byte) (int, error) {
	if f.fails > 0 {
		f.fails--

		return 0, errors.New("derp")
	}

	return f.buf.Write(p)
}

func TestWriterRetries(t *testing.T) {
	elb := &bytes.Buffer{}
	log := textLogger(elb)

	fw := &flakyWriter{fails: 1}
	w := NewWriter(fw, 2, log)
	w.retryDelay = 0

	require.NoError(t, w.Write(map[string]int{"sequence": 1}))
	assert.Contains(t, fw.buf.String(), "\"sequence\":1")
	assert.Equal(t, "level=WARN msg=\"failed to write event, retrying\" attempt=1 delay=0s err=derp\n", elb.String())

	// No retry message after the last attempt
	elb.Reset()
	fw = &flakyWriter{fails: 2}
	w = NewWriter(fw, 2, log)
	w.retryDelay = 0

	assert.EqualError(t, w.Write(map[string]int{"sequence": 2}), "derp")
	assert.Equal(t, "level=WARN msg=\"failed to write event, retrying\" attempt=1 delay=0s err=derp\n", elb.String())
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
