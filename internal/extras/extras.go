// Package extras enriches audit messages with process context such as
// cgroup and container details.
package extras

import (
	"fmt"
	"log/slog"

	"github.com/yousysadmin/go-audit/internal/audit"
	"github.com/yousysadmin/go-audit/internal/config"
)

// constructor returns a parser, or nil when the parser is disabled.
type constructor func(cfg config.Extras, log *slog.Logger) (audit.ExtraParser, error)

var constructors []constructor

// register adds a parser constructor, called from init in each parser file.
func register(c constructor) {
	constructors = append(constructors, c)
}

// New builds every enabled extra parser.
func New(cfg config.Extras, log *slog.Logger) ([]audit.ExtraParser, error) {
	var parsers []audit.ExtraParser

	for _, c := range constructors {
		p, err := c(cfg, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create extra parser: %w", err)
		}

		if p != nil {
			parsers = append(parsers, p)
		}
	}

	return parsers, nil
}
