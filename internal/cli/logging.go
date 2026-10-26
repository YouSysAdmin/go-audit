package cli

import (
	"log/slog"

	logger "github.com/yousysadmin/go-logger"

	"github.com/yousysadmin/go-audit/internal/config"
)

// buildLogger turns the logging config into one sink for the daemon's own lines.
func buildLogger(cfg config.Logging) (*slog.Logger, error) {
	return logger.New(logger.Sink{
		Level:  cfg.Level,
		Output: cfg.Output,
		Format: cfg.Format,
		// Color only applies to text, and only when the output is a terminal
		Color: cfg.Color && cfg.Format == logger.FormatText,
	})
}
