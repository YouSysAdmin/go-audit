// Package rules installs the configured audit rules with auditctl.
package rules

import (
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// Executor runs a command with arguments.
type Executor func(name string, args ...string) error

// Exec runs the command and waits for it.
func Exec(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil && len(out) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}

	return err
}

// Apply flushes existing audit rules and adds each non-empty rule in order.
func Apply(rules []string, run Executor, log *slog.Logger) error {
	if len(rules) == 0 {
		return errors.New("no audit rules found")
	}

	if err := run("auditctl", "-D"); err != nil {
		return fmt.Errorf("failed to flush existing audit rules: %w", err)
	}

	log.Info("flushed existing audit rules")

	for i, rule := range rules {
		if strings.TrimSpace(rule) == "" {
			continue
		}

		if err := run("auditctl", strings.Fields(rule)...); err != nil {
			return fmt.Errorf("failed to add rule #%d: %w", i+1, err)
		}

		log.Info("added audit rule", "n", i+1)
	}

	return nil
}
