package event

import (
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/yousysadmin/go-audit/internal/audit"
	"github.com/yousysadmin/go-audit/internal/syscalls"
)

// unsetID is (uint32)-1, used by the kernel for ids that are not set.
const unsetID = "4294967295"

// Options controls the fields added to every event.
type Options struct {
	Host string
	Tags map[string]string
	Raw  bool
}

// Builder turns message groups into events. It is safe for concurrent use.
type Builder struct {
	opts   Options
	users  *nameCache
	groups *nameCache
}

// NewBuilder returns a Builder resolving user and group names from the system.
func NewBuilder(opts Options) *Builder {
	return &Builder{opts: opts, users: newUserCache(), groups: newGroupCache()}
}

// Build converts a group into an event.
func (b *Builder) Build(g *audit.MessageGroup) *Event {
	ev := &Event{
		Time:     formatTime(g.AuditTime),
		Sequence: g.Seq,
		Host:     b.opts.Host,
		Tags:     b.opts.Tags,
		Records:  make([]Record, 0, len(g.Msgs)),
	}

	var execve map[string]string

	for _, m := range g.Msgs {
		f := m.Fields()

		rec := Record{Type: audit.TypeName(m.Type), TypeID: m.Type, Fields: f}
		if b.opts.Raw {
			rec.Raw = m.Data
		}

		ev.Records = append(ev.Records, rec)

		switch m.Type {
		case audit.TypeSyscall:
			b.syscall(ev, f)
		case audit.TypeExecve:
			// Long argument lists are split over several EXECVE records
			if execve == nil {
				execve = make(map[string]string, len(f))
			}

			maps.Copy(execve, f)
		case audit.TypeProctitle:
			process(ev).Title = f["proctitle"]
		case audit.TypeCwd:
			process(ev).Cwd = f["cwd"]
		case audit.TypePath:
			ev.Paths = append(ev.Paths, path(f))
		case audit.TypeSockaddr:
			ev.Network = parseSockaddr(f["saddr"])
		}

		if m.ContainerID != "" && ev.Container == nil {
			ev.Container = &Container{ID: m.ContainerID}
		}

		if m.CgroupRoot != "" && ev.Cgroup == "" {
			ev.Cgroup = m.CgroupRoot
		}
	}

	if execve != nil {
		process(ev).Args = execveArgs(execve)
	}

	return ev
}

// syscall fills key, syscall, process and user from the SYSCALL record.
func (b *Builder) syscall(ev *Event, f map[string]string) {
	if key := f["key"]; key != "" && key != "(null)" {
		ev.Key = key
	}

	sc := &Syscall{
		Nr:   parseInt(f["syscall"]),
		Name: syscalls.NameOf(f["arch"], f["syscall"]),
		Arch: syscalls.Arch(f["arch"]),
		Exit: parseInt64(f["exit"]),
	}

	if sc.Arch == "" {
		sc.Arch = f["arch"]
	}

	switch f["success"] {
	case "yes":
		sc.Success = new(true)
	case "no":
		sc.Success = new(false)
	}

	ev.Syscall = sc

	p := process(ev)
	p.PID = parseInt(f["pid"])
	p.PPID = parseInt(f["ppid"])
	p.Comm = f["comm"]
	p.Exe = f["exe"]

	if tty := f["tty"]; tty != "(none)" {
		p.TTY = tty
	}

	if ses := f["ses"]; ses != unsetID {
		p.Session = parseUint32(ses)
	}

	ev.User = &User{
		AUID:     parseUint32(f["auid"]),
		AUIDName: b.users.name(f["auid"]),
		UID:      parseUint32(f["uid"]),
		UIDName:  b.users.name(f["uid"]),
		EUID:     parseUint32(f["euid"]),
		EUIDName: b.users.name(f["euid"]),
		SUID:     parseUint32(f["suid"]),
		FSUID:    parseUint32(f["fsuid"]),
		GID:      parseUint32(f["gid"]),
		GIDName:  b.groups.name(f["gid"]),
		EGID:     parseUint32(f["egid"]),
		SGID:     parseUint32(f["sgid"]),
		FSGID:    parseUint32(f["fsgid"]),
	}
}

// process returns ev.Process, created on first use since several records add to it.
func process(ev *Event) *Process {
	if ev.Process == nil {
		ev.Process = &Process{}
	}

	return ev.Process
}

// path converts a PATH record.
func path(f map[string]string) Path {
	p := Path{
		Item:     parseInt(f["item"]),
		Inode:    parseUint64(f["inode"]),
		Dev:      f["dev"],
		Mode:     f["mode"],
		OUID:     parseUint32(f["ouid"]),
		OGID:     parseUint32(f["ogid"]),
		Nametype: f["nametype"],
	}

	if name := f["name"]; name != "(null)" {
		p.Name = name
	}

	return p
}

// execveArgs joins a0..aN, a long argument comes as a1[0], a1[1] and so on.
func execveArgs(f map[string]string) []string {
	argc, err := strconv.Atoi(f["argc"])
	if err != nil || argc <= 0 {
		return nil
	}

	args := make([]string, 0, argc)
	for i := range argc {
		key := "a" + strconv.Itoa(i)
		if v, ok := f[key]; ok {
			args = append(args, v)

			continue
		}

		var sb strings.Builder
		for j := 0; ; j++ {
			chunk, ok := f[key+"["+strconv.Itoa(j)+"]"]
			if !ok {
				break
			}

			sb.WriteString(chunk)
		}

		args = append(args, sb.String())
	}

	return args
}

// formatTime turns the audit "seconds.millis" stamp into RFC 3339 in UTC.
func formatTime(ts string) string {
	sec, frac, _ := strings.Cut(ts, ".")

	s, err := strconv.ParseInt(sec, 10, 64)
	if err != nil {
		return ts
	}

	var ns int64
	if frac != "" {
		f := (frac + "000000000")[:9]
		if ns, err = strconv.ParseInt(f, 10, 64); err != nil {
			return ts
		}
	}

	return time.Unix(s, ns).UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// The parse helpers return nil for a missing or malformed value, so the field
// is left out of the event while a real 0 is kept.

func parseInt(s string) *int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}

	return &v
}

func parseInt64(s string) *int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}

	return &v
}

func parseUint32(s string) *uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil
	}

	return new(uint32(v))
}

func parseUint64(s string) *uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return nil
	}

	return &v
}
