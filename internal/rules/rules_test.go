package rules

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApply(t *testing.T) {
	log := discard

	t.Run("no rules", func(t *testing.T) {
		called := false
		err := Apply(nil, func(string, ...string) error { called = true; return nil }, log)
		assert.EqualError(t, err, "no audit rules found")
		assert.False(t, called, "existing rules must not be flushed when there is nothing to add")
	})

	t.Run("flush fails", func(t *testing.T) {
		err := Apply([]string{"-a -1"}, func(s string, a ...string) error {
			if s == "auditctl" && a[0] == "-D" {
				return errors.New("testing")
			}

			return nil
		}, log)
		assert.EqualError(t, err, "failed to flush existing audit rules: testing")
	})

	t.Run("add fails", func(t *testing.T) {
		r := 0
		err := Apply([]string{"-a -1 -2", "", "-a -3 -4"}, func(_ string, a ...string) error {
			if a[0] != "-D" {
				return errors.New("testing rule")
			}

			r++

			return nil
		}, log)
		assert.Equal(t, 1, r)
		assert.EqualError(t, err, "failed to add rule #1: testing rule")
	})

	t.Run("all rules added", func(t *testing.T) {
		lb := &bytes.Buffer{}
		var got [][]string
		err := Apply([]string{"-a -1 -2", "", "  ", "-a -3 -4"}, func(_ string, a ...string) error {
			got = append(got, a)

			return nil
		}, textLogger(lb))
		assert.NoError(t, err)
		assert.Equal(t, [][]string{{"-D"}, {"-a", "-1", "-2"}, {"-a", "-3", "-4"}}, got)
		assert.Equal(t, "level=INFO msg=\"flushed existing audit rules\"\nlevel=INFO msg=\"added audit rule\" n=1\nlevel=INFO msg=\"added audit rule\" n=4\n", lb.String())
	})
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
