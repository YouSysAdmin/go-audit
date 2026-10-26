package output

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"log/syslog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/yousysadmin/go-audit/internal/config"
)

// New builds the single enabled output. When it is the file output, the
// file is reopened on SIGUSR1 until ctx is done.
func New(ctx context.Context, cfg config.Output, log *slog.Logger) (*Writer, error) {
	enabled := 0
	for _, on := range []bool{cfg.Syslog.Enabled, cfg.File.Enabled, cfg.Stdout.Enabled} {
		if on {
			enabled++
		}
	}

	switch {
	case enabled == 0:
		return nil, errors.New("no outputs were configured")
	case enabled > 1:
		return nil, errors.New("only one output can be enabled at a time")
	}

	switch {
	case cfg.Syslog.Enabled:
		return NewSyslog(cfg.Syslog, log)
	case cfg.File.Enabled:
		w, err := NewFile(cfg.File, log)
		if err != nil {
			return nil, err
		}

		HandleRotation(ctx, cfg.File, w, log)

		return w, nil
	default:
		return NewStdout(cfg.Stdout, log)
	}
}

// NewSyslog returns a Writer sending to a syslog daemon.
func NewSyslog(cfg config.Syslog, log *slog.Logger) (*Writer, error) {
	if cfg.Attempts < 1 {
		return nil, fmt.Errorf("output attempts for syslog must be at least 1, %d provided", cfg.Attempts)
	}

	w, err := syslog.Dial(cfg.Network, cfg.Address, syslog.Priority(cfg.Priority), cfg.Tag)
	if err != nil {
		return nil, fmt.Errorf("failed to open syslog writer: %w", err)
	}

	return NewWriter(w, cfg.Attempts, log), nil
}

// NewStdout returns a Writer on standard output and moves informational
// log lines to stderr so they do not mix with events.
func NewStdout(cfg config.Stdout, log *slog.Logger) (*Writer, error) {
	if cfg.Attempts < 1 {
		return nil, fmt.Errorf("output attempts for stdout must be at least 1, %d provided", cfg.Attempts)
	}

	return NewWriter(os.Stdout, cfg.Attempts, log), nil
}

// NewFile returns a Writer appending to a file owned by the configured user and group.
func NewFile(cfg config.File, log *slog.Logger) (*Writer, error) {
	if cfg.Attempts < 1 {
		return nil, fmt.Errorf("output attempts for file must be at least 1, %d provided", cfg.Attempts)
	}

	f, err := openFile(cfg)
	if err != nil {
		return nil, err
	}

	return NewWriter(f, cfg.Attempts, log), nil
}

// openFile opens the output file for appending and applies its mode and owner.
// The owner is looked up first, so a bad user or group does not create the file.
func openFile(cfg config.File) (*os.File, error) {
	mode := os.FileMode(cfg.Mode)
	if mode < 1 {
		return nil, errors.New("output file mode should be greater than 0000")
	}

	uid, gid, err := lookupOwner(cfg.User, cfg.Group)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, mode)
	if err != nil {
		return nil, fmt.Errorf("failed to open output file: %w", err)
	}

	if err := f.Chmod(mode); err != nil {
		_ = f.Close()

		return nil, fmt.Errorf("failed to set file permissions: %w", err)
	}

	if err := f.Chown(uid, gid); err != nil {
		_ = f.Close()

		return nil, fmt.Errorf("could not chown output file: %w", err)
	}

	return f, nil
}

// lookupOwner resolves a user and a group name to numeric ids.
func lookupOwner(uname, gname string) (uid, gid int, err error) {
	u, err := user.Lookup(uname)
	if err != nil {
		return 0, 0, fmt.Errorf("could not find uid for user %s: %w", uname, err)
	}

	g, err := user.LookupGroup(gname)
	if err != nil {
		return 0, 0, fmt.Errorf("could not find gid for group %s: %w", gname, err)
	}

	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("found uid could not be parsed: %w", err)
	}

	gid, err = strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("found gid could not be parsed: %w", err)
	}

	return uid, gid, nil
}

// HandleRotation reopens the output file on SIGUSR1, for use after log rotation.
// The signal is subscribed before it returns, the reopening runs until ctx is done.
func HandleRotation(ctx context.Context, cfg config.File, w *Writer, log *slog.Logger) {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGUSR1)

	go rotate(ctx, sigc, cfg, w, log)
}

// rotate swaps in a newly opened file on every signal and closes the old one.
func rotate(ctx context.Context, sigc chan os.Signal, cfg config.File, w *Writer, log *slog.Logger) {
	defer signal.Stop(sigc)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sigc:
		}

		f, err := openFile(cfg)
		if err != nil {
			// Keep writing to the old file rather than losing events
			log.Error("failed to reopen output file, still writing to the old one", "path", cfg.Path, "err", err)

			continue
		}

		if old, ok := w.swap(f).(*os.File); ok {
			if err := old.Close(); err != nil {
				log.Error("failed to close old output file", "err", err)
			}
		}
	}
}
