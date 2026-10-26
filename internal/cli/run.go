package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yousysadmin/go-audit/internal/audit"
	"github.com/yousysadmin/go-audit/internal/config"
	"github.com/yousysadmin/go-audit/internal/event"
	"github.com/yousysadmin/go-audit/internal/extras"
	"github.com/yousysadmin/go-audit/internal/netlink"
	"github.com/yousysadmin/go-audit/internal/output"
	"github.com/yousysadmin/go-audit/internal/rules"
)

// receiveTimeout wakes the receive loop when the socket is idle, so old
// groups are flushed and shutdown is noticed.
const receiveTimeout = time.Second

// run loads the config, installs the audit rules and processes events until
// SIGINT or SIGTERM, then writes any pending groups.
func run(ctx context.Context, configFile string) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(configFile)
	if err != nil {
		return err
	}

	log, err := buildLogger(cfg.Logging)
	if err != nil {
		return err
	}

	out, err := output.New(ctx, cfg.Output, log)
	if err != nil {
		return err
	}

	opts := event.Options{Tags: cfg.Tags, Raw: cfg.Event.Raw}
	if cfg.Event.Host {
		if opts.Host, err = os.Hostname(); err != nil {
			return fmt.Errorf("reading hostname: %w", err)
		}
	}

	writer := event.NewWriter(event.NewBuilder(opts), out)

	if err := rules.Apply(cfg.Rules, rules.Exec, log); err != nil {
		return err
	}

	for _, f := range cfg.Filters {
		log.Info("filter enabled", "syscall", f.Syscall, "message_type", f.MessageType, "regex", f.Regex.String())
	}

	parsers, err := extras.New(cfg.Extras, log)
	if err != nil {
		return err
	}

	client, err := netlink.New(ctx, cfg.SocketBuffer.Receive, receiveTimeout, log)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	marshaller := audit.NewMarshaller(writer, audit.Options{
		EventMin:      cfg.Events.Min,
		EventMax:      cfg.Events.Max,
		TrackMessages: cfg.MessageTracking.Enabled,
		LogOutOfOrder: cfg.MessageTracking.LogOutOfOrder,
		MaxOutOfOrder: cfg.MessageTracking.MaxOutOfOrder,
	}, cfg.Filters, parsers, log)

	log.Info("processing events", "min", cfg.Events.Min, "max", cfg.Events.Max)

	return consume(ctx, client, marshaller, log)
}

// receiver is the part of the netlink client the loop needs.
type receiver interface {
	Receive() (*syscall.NetlinkMessage, error)
}

func consume(ctx context.Context, client receiver, m *audit.Marshaller, log *slog.Logger) error {
	for {
		if ctx.Err() != nil {
			log.Info("shutting down", "pending", m.Pending())

			return m.Flush()
		}

		msg, err := client.Receive()
		if errors.Is(err, netlink.ErrTimeout) {
			if err := m.FlushOld(); err != nil {
				return err
			}

			continue
		}

		if errors.Is(err, syscall.EBADF) {
			return err
		}

		if err != nil {
			log.Error("failed to receive message", "err", err)

			continue
		}

		if err := m.Consume(msg); err != nil {
			return err
		}
	}
}
