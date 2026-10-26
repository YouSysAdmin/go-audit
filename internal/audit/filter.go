package audit

import (
	"regexp"

	"github.com/yousysadmin/go-audit/internal/syscalls"
)

// Filter drops a message group when its syscall matches and any message of
// MessageType has data matching Regex. Syscall is a name such as connect,
// or a number, which is architecture specific.
type Filter struct {
	Syscall     string
	MessageType uint16
	Regex       *regexp.Regexp
}

// filterSet indexes filters as syscall -> message type -> regexes.
type filterSet map[string]map[uint16][]*regexp.Regexp

func newFilterSet(filters []Filter) filterSet {
	fs := make(filterSet)

	for _, f := range filters {
		if _, ok := fs[f.Syscall]; !ok {
			fs[f.Syscall] = make(map[uint16][]*regexp.Regexp)
		}

		fs[f.Syscall][f.MessageType] = append(fs[f.Syscall][f.MessageType], f.Regex)
	}

	return fs
}

func (fs filterSet) drop(msg *MessageGroup) bool {
	if len(fs) == 0 {
		return false
	}

	byType, ok := fs[msg.Syscall]
	if !ok {
		byType, ok = fs[syscalls.NameOf(msg.Arch, msg.Syscall)]
	}

	if !ok {
		return false
	}

	for _, m := range msg.Msgs {
		for _, re := range byType[m.Type] {
			if re.MatchString(m.Data) {
				return true
			}
		}
	}

	return false
}
