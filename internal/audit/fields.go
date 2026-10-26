package audit

import (
	"encoding/hex"
	"regexp"
	"strings"
)

// hexFields hold untrusted strings. The kernel hex encodes them, unquoted,
// when they contain spaces, quotes or control characters.
var hexFields = map[string]bool{
	"acct":      true,
	"cmd":       true,
	"comm":      true,
	"cwd":       true,
	"data":      true,
	"dir":       true,
	"exe":       true,
	"file":      true,
	"key":       true,
	"name":      true,
	"new":       true,
	"ocomm":     true,
	"old":       true,
	"path":      true,
	"proctitle": true,
	"root_dir":  true,
	"watch":     true,
}

// execveArg matches EXECVE arguments, a0 or a chunk of a long one, a1[0].
var execveArg = regexp.MustCompile(`^a\d+(\[\d+\])?$`)

// ParseFields splits record data into key value pairs and decodes hex encoded
// strings. A single quoted msg='...' value is parsed into the same map.
func ParseFields(recordType uint16, data string) map[string]string {
	fields := make(map[string]string, 16)
	parseInto(fields, recordType, data)

	return fields
}

// parseInto reads `key=value` pairs separated by spaces. A value is either
// "double quoted", 'single quoted' or runs to the next space.
func parseInto(fields map[string]string, recordType uint16, data string) {
	for data != "" {
		data = strings.TrimLeft(data, " ")

		eq := strings.IndexByte(data, '=')
		if eq <= 0 {
			return
		}

		key := data[:eq]
		if sp := strings.LastIndexByte(key, ' '); sp >= 0 {
			// A bare word without a value, skip it
			key = key[sp+1:]
		}

		rest := data[eq+1:]

		var (
			value  string
			quoted bool
		)

		switch {
		case strings.HasPrefix(rest, `"`), strings.HasPrefix(rest, "'"):
			q := rest[:1]
			end := strings.Index(rest[1:], q)
			if end < 0 {
				value, data = rest[1:], ""
			} else {
				value, data = rest[1:end+1], rest[end+2:]
			}

			quoted = true

			if q == "'" && key == "msg" {
				parseInto(fields, recordType, value)

				continue
			}
		default:
			end := strings.IndexByte(rest, ' ')
			if end < 0 {
				value, data = rest, ""
			} else {
				value, data = rest[:end], rest[end:]
			}
		}

		if !quoted && isHexField(recordType, key) {
			value = decodeHex(value)
		}

		switch key {
		case "proctitle":
			// argv is NUL separated
			value = strings.TrimRight(strings.ReplaceAll(value, "\x00", " "), " ")
		case "key":
			// Several rule keys are joined with \x01
			value = strings.ReplaceAll(value, "\x01", ",")
		}

		fields[key] = value
	}
}

func isHexField(recordType uint16, key string) bool {
	if hexFields[key] {
		return true
	}

	return recordType == TypeExecve && execveArg.MatchString(key)
}

// decodeHex decodes an even length hex string, anything else is returned as is.
func decodeHex(v string) string {
	if v == "" || len(v)%2 != 0 {
		return v
	}

	b, err := hex.DecodeString(v)
	if err != nil {
		return v
	}

	return string(b)
}
