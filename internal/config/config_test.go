package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "go-audit.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

	return path
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, ""))
	require.NoError(t, err)

	assert.Equal(t, uint16(1300), cfg.Events.Min)
	assert.Equal(t, uint16(1399), cfg.Events.Max)
	assert.True(t, cfg.MessageTracking.Enabled)
	assert.False(t, cfg.MessageTracking.LogOutOfOrder)
	assert.Equal(t, 500, cfg.MessageTracking.MaxOutOfOrder)
	assert.False(t, cfg.Output.Syslog.Enabled)
	assert.Equal(t, 132, cfg.Output.Syslog.Priority)
	assert.Equal(t, "go-audit", cfg.Output.Syslog.Tag)
	assert.Equal(t, 3, cfg.Output.Syslog.Attempts)
	assert.Equal(t, 3, cfg.Output.Stdout.Attempts)
	assert.Equal(t, 3, cfg.Output.File.Attempts)
	assert.Equal(t, "/var/log/go-audit/go-audit.log", cfg.Output.File.Path)
	assert.Equal(t, 0o600, cfg.Output.File.Mode)
	assert.Equal(t, "root", cfg.Output.File.User)
	assert.Equal(t, "root", cfg.Output.File.Group)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.Equal(t, "stderr", cfg.Logging.Output)
	assert.False(t, cfg.Logging.Color)
	assert.Empty(t, cfg.Filters)
}

func TestLoadParseError(t *testing.T) {
	cfg, err := Load(writeConfig(t, "this is bad"))
	assert.ErrorContains(t, err, "While parsing config")
	assert.Nil(t, cfg)
}

// The reference example documents every option with its default, so loading
// it must give the defaults, apart from the values it sets on purpose.
func TestLoadExampleMatchesDefaults(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "go-audit.example.yaml"))
	require.NoError(t, err)

	cfg, err := Load(writeConfig(t, string(example)))
	require.NoError(t, err)

	defaults, err := Load(writeConfig(t, ""))
	require.NoError(t, err)

	assert.True(t, cfg.Output.Stdout.Enabled)
	assert.Equal(t, []string{
		"-a always,exit -F arch=b64 -S execve",
		"-a always,exit -F arch=b32 -S execve",
		"-e 1",
	}, cfg.Rules)
	require.Len(t, cfg.Filters, 1)
	assert.Equal(t, "bind", cfg.Filters[0].Syscall)
	assert.Equal(t, uint16(1306), cfg.Filters[0].MessageType)
	assert.Equal(t, "saddr=(10..|0A..)", cfg.Filters[0].Regex.String())
	assert.Empty(t, cfg.Tags)

	cfg.Output.Stdout.Enabled = false
	cfg.Rules, cfg.Filters, cfg.Tags = nil, nil, nil

	assert.Equal(t, defaults, cfg)
}

func TestLoggingOnStdoutConflictsWithStdoutOutput(t *testing.T) {
	_, err := Load(writeConfig(t, "output:\n  stdout:\n    enabled: true\nlogging:\n  output: stdout\n"))
	assert.EqualError(t, err, "logging.output cannot be stdout while output.stdout is enabled")

	_, err = Load(writeConfig(t, "output:\n  stdout:\n    enabled: true\n"))
	assert.NoError(t, err)
}

func TestLoadServerExample(t *testing.T) {
	t.Setenv("ENV", "prod")
	t.Setenv("DATACENTER", "")

	example, err := os.ReadFile(filepath.Join("..", "..", "examples", "go-audit.yaml"))
	require.NoError(t, err)

	cfg, err := Load(writeConfig(t, string(example)))
	require.NoError(t, err)

	assert.True(t, cfg.Output.File.Enabled)
	assert.Equal(t, 0o600, cfg.Output.File.Mode)
	assert.Equal(t, "stderr", cfg.Logging.Output)
	assert.True(t, cfg.Extras.Cgroups.Enabled)
	assert.True(t, cfg.Extras.Containers.Enabled)
	assert.Equal(t, "-b 8192", cfg.Rules[0])
	assert.Equal(t, "-e 1", cfg.Rules[len(cfg.Rules)-1])
	require.Len(t, cfg.Filters, 1)
	assert.Equal(t, "connect", cfg.Filters[0].Syscall)
	assert.True(t, cfg.Event.Host)
	assert.Equal(t, map[string]string{"env": "prod"}, cfg.Tags)
}

func TestTagsAndEvent(t *testing.T) {
	t.Setenv("GO_AUDIT_TEST_DC", "fra1")

	cfg, err := Load(writeConfig(t, "tags:\n  Env: prod\n  dc: ${GO_AUDIT_TEST_DC}\n  missing: x${GO_AUDIT_TEST_UNSET}\n  empty: ${GO_AUDIT_TEST_UNSET}\nevent:\n  raw: true\n"))
	require.NoError(t, err)

	assert.Equal(t, map[string]string{"env": "prod", "dc": "fra1", "missing": "x"}, cfg.Tags)
	assert.True(t, cfg.Event.Host, "host defaults to true")
	assert.True(t, cfg.Event.Raw)

	cfg, err = Load(writeConfig(t, "event:\n  host: false\n"))
	require.NoError(t, err)
	assert.False(t, cfg.Event.Host)
	assert.Nil(t, cfg.Tags)
}

func TestFilters(t *testing.T) {
	tests := []struct {
		name    string
		filters any
		err     string
	}{
		{"outer value", 1, "could not parse filters object"},
		{"inner value", []any{"bad filter definition"}, "could not parse filter 1: 'bad filter definition'"},
		{"message type string", []any{map[string]any{"message_type": "bad message type"}},
			"`message_type` in filter 1 could not be parsed, value: `bad message type`: strconv.ParseUint: parsing \"bad message type\": invalid syntax"},
		{"message type unknown", []any{map[string]any{"message_type": false}}, "`message_type` in filter 1 could not be parsed, value: `false`"},
		{"message type range", []any{map[string]any{"message_type": 70000}}, "`message_type` in filter 1 is out of range, value: `70000`"},
		{"regex not string", []any{map[string]any{"regex": false}}, "`regex` in filter 1 could not be parsed, value: `false`"},
		{"regex invalid", []any{map[string]any{"regex": "["}},
			"`regex` in filter 1 could not be parsed, value: `[`: error parsing regexp: missing closing ]: `[`"},
		{"syscall type", []any{map[string]any{"syscall": []string{}}}, "`syscall` in filter 1 could not be parsed, value: `[]`"},
		{"missing regex", []any{map[string]any{"syscall": "1", "message_type": "1"}}, "filter 1 is missing the `regex` entry"},
		{"missing message type", []any{map[string]any{"syscall": "1", "regex": "1"}}, "filter 1 is missing the `message_type` entry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.Set("filters", tt.filters)

			_, err := FromViper(v)
			assert.EqualError(t, err, tt.err)
		})
	}

	for name, entry := range map[string]map[string]any{
		"strings": {"message_type": "1", "regex": "1", "syscall": "1"},
		"ints":    {"message_type": 1, "regex": "1", "syscall": 1},
	} {
		t.Run(name, func(t *testing.T) {
			v := viper.New()
			v.Set("filters", []any{entry})

			cfg, err := FromViper(v)
			require.NoError(t, err)
			require.Len(t, cfg.Filters, 1)
			assert.Equal(t, "1", cfg.Filters[0].Syscall)
			assert.Equal(t, uint16(1), cfg.Filters[0].MessageType)
			assert.Equal(t, "1", cfg.Filters[0].Regex.String())
		})
	}
}
