// Package config loads and validates the go-audit YAML configuration.
package config

import (
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"regexp"
	"strconv"

	"github.com/spf13/viper"

	"github.com/yousysadmin/go-audit/internal/audit"
	"github.com/yousysadmin/go-audit/pkg"
)

// Config is the full daemon configuration.
type Config struct {
	SocketBuffer    SocketBuffer    `mapstructure:"socket_buffer"`
	Events          Events          `mapstructure:"events"`
	MessageTracking MessageTracking `mapstructure:"message_tracking"`
	Output          Output          `mapstructure:"output"`
	Logging         Logging         `mapstructure:"logging"`
	Rules           []string        `mapstructure:"rules"`
	Extras          Extras          `mapstructure:"extras"`
	Event           Event           `mapstructure:"event"`

	// Tags are added to every event, ${VAR} in values is expanded from the environment.
	Tags map[string]string `mapstructure:"tags"`

	// Filters is parsed by hand to keep per-entry error messages.
	Filters []audit.Filter `mapstructure:"-"`
}

// SocketBuffer configures the netlink socket.
type SocketBuffer struct {
	Receive int `mapstructure:"receive"`
}

// Events is the inclusive range of audit message types to keep.
type Events struct {
	Min uint16 `mapstructure:"min"`
	Max uint16 `mapstructure:"max"`
}

// MessageTracking configures sequence gap detection.
type MessageTracking struct {
	Enabled       bool `mapstructure:"enabled"`
	LogOutOfOrder bool `mapstructure:"log_out_of_order"`
	MaxOutOfOrder int  `mapstructure:"max_out_of_order"`
}

// Output holds every output, exactly one must be enabled.
type Output struct {
	Stdout Stdout `mapstructure:"stdout"`
	Syslog Syslog `mapstructure:"syslog"`
	File   File   `mapstructure:"file"`
}

// Stdout writes events to standard output.
type Stdout struct {
	Enabled  bool `mapstructure:"enabled"`
	Attempts int  `mapstructure:"attempts"`
}

// Syslog writes events to a syslog daemon.
type Syslog struct {
	Enabled  bool   `mapstructure:"enabled"`
	Attempts int    `mapstructure:"attempts"`
	Network  string `mapstructure:"network"`
	Address  string `mapstructure:"address"`
	Priority int    `mapstructure:"priority"`
	Tag      string `mapstructure:"tag"`
}

// File writes events to a local file.
type File struct {
	Enabled  bool   `mapstructure:"enabled"`
	Attempts int    `mapstructure:"attempts"`
	Path     string `mapstructure:"path"`
	Mode     int    `mapstructure:"mode"`
	User     string `mapstructure:"user"`
	Group    string `mapstructure:"group"`
}

// Logging configures the daemon's own log lines, not the audit events.
type Logging struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
	Color  bool   `mapstructure:"color"`
}

// Event controls fields added to every event.
type Event struct {
	// Host adds the "host" field with the system hostname
	Host bool `mapstructure:"host"`
	// Raw keeps the unparsed record text in records[].raw
	Raw bool `mapstructure:"raw"`
}

// Extras configures optional message enrichment.
type Extras struct {
	Cgroups    Cgroups    `mapstructure:"cgroups"`
	Containers Containers `mapstructure:"containers"`
}

// Cgroups adds the cgroup root of the process.
type Cgroups struct {
	Enabled bool `mapstructure:"enabled"`
}

// Containers adds the container id of the process, read from its cgroup path.
type Containers struct {
	Enabled  bool `mapstructure:"enabled"`
	PidCache int  `mapstructure:"pid_cache"`
}

// Load reads the config file at path and applies defaults.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	return FromViper(v)
}

// FromViper decodes an already populated viper instance.
func FromViper(v *viper.Viper) (*Config, error) {
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}

	filters, err := parseFilters(v.Get("filters"))
	if err != nil {
		return nil, err
	}

	cfg.Filters = filters

	for k, val := range cfg.Tags {
		// A tag whose variable is unset is dropped rather than sent empty
		if val = os.ExpandEnv(val); val == "" {
			delete(cfg.Tags, k)

			continue
		}

		cfg.Tags[k] = val
	}

	if cfg.Output.Stdout.Enabled && cfg.Logging.Output == "stdout" {
		return nil, errors.New("logging.output cannot be stdout while output.stdout is enabled")
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("events.min", 1300)
	v.SetDefault("events.max", 1399)
	v.SetDefault("message_tracking.enabled", true)
	v.SetDefault("message_tracking.log_out_of_order", false)
	v.SetDefault("message_tracking.max_out_of_order", 500)
	v.SetDefault("output.syslog.enabled", false)
	v.SetDefault("output.syslog.priority", int(syslog.LOG_LOCAL0|syslog.LOG_WARNING))
	v.SetDefault("output.syslog.tag", pkg.AppName)
	v.SetDefault("output.syslog.attempts", 3)
	v.SetDefault("output.stdout.attempts", 3)
	v.SetDefault("output.file.attempts", 3)
	v.SetDefault("output.file.path", "/var/log/go-audit/go-audit.log")
	v.SetDefault("output.file.mode", 0o600)
	v.SetDefault("output.file.user", "root")
	v.SetDefault("output.file.group", "root")
	v.SetDefault("event.host", true)
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stderr")
}

func parseFilters(raw any) ([]audit.Filter, error) {
	if raw == nil {
		return nil, nil
	}

	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("could not parse filters object")
	}

	filters := make([]audit.Filter, 0, len(list))
	for i, item := range list {
		f, err := parseFilter(i+1, item)
		if err != nil {
			return nil, err
		}

		filters = append(filters, f)
	}

	return filters, nil
}

func parseFilter(n int, item any) (audit.Filter, error) {
	var af audit.Filter

	fields, ok := item.(map[string]any)
	if !ok {
		return af, fmt.Errorf("could not parse filter %d: '%+v'", n, item)
	}

	for k, v := range fields {
		switch k {
		case "message_type":
			switch ev := v.(type) {
			case string:
				fv, err := strconv.ParseUint(ev, 10, 16)
				if err != nil {
					return af, fmt.Errorf("`message_type` in filter %d could not be parsed, value: `%+v`: %w", n, v, err)
				}

				af.MessageType = uint16(fv)
			case int:
				if ev < 0 || ev > 0xffff {
					return af, fmt.Errorf("`message_type` in filter %d is out of range, value: `%+v`", n, v)
				}

				af.MessageType = uint16(ev)
			default:
				return af, fmt.Errorf("`message_type` in filter %d could not be parsed, value: `%+v`", n, v)
			}

		case "regex":
			re, ok := v.(string)
			if !ok {
				return af, fmt.Errorf("`regex` in filter %d could not be parsed, value: `%+v`", n, v)
			}

			var err error
			if af.Regex, err = regexp.Compile(re); err != nil {
				return af, fmt.Errorf("`regex` in filter %d could not be parsed, value: `%+v`: %w", n, v, err)
			}

		case "syscall":
			switch ev := v.(type) {
			case string:
				af.Syscall = ev
			case int:
				af.Syscall = strconv.Itoa(ev)
			default:
				return af, fmt.Errorf("`syscall` in filter %d could not be parsed, value: `%+v`", n, v)
			}
		}
	}

	if af.Regex == nil {
		return af, fmt.Errorf("filter %d is missing the `regex` entry", n)
	}

	if af.MessageType == 0 {
		return af, fmt.Errorf("filter %d is missing the `message_type` entry", n)
	}

	return af, nil
}
