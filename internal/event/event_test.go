package event

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yousysadmin/go-audit/internal/audit"
)

// fakeNames resolves only the given ids.
func fakeNames(known map[string]string) *nameCache {
	return &nameCache{
		names: make(map[string]string),
		lookup: func(id string) (string, error) {
			if name, ok := known[id]; ok {
				return name, nil
			}

			return "", errors.New("unknown")
		},
	}
}

func testBuilder(opts Options) *Builder {
	b := NewBuilder(opts)
	b.users = fakeNames(map[string]string{"0": "root", "1000": "ubuntu"})
	b.groups = fakeNames(map[string]string{"1000": "ubuntu"})

	return b
}

func group(seq int, ts string, records ...*audit.Message) *audit.MessageGroup {
	g := audit.NewMessageGroup(records[0])
	g.Seq = seq
	g.AuditTime = ts
	for _, r := range records[1:] {
		g.AddMessage(r)
	}

	return g
}

func lsGroup() *audit.MessageGroup {
	return group(1222763, "1459376866.885",
		&audit.Message{Type: 1300, Data: `arch=c000003e syscall=59 success=yes exit=0 a0=cc4e68 a1=d10bc8 a2=c69808 a3=7fff2a700900 items=2 ppid=11552 pid=11623 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=35 comm="ls" exe="/bin/ls" key="user-commands"`,
			ContainerID: "5c69ff1a4edf85228df5153f36cacbdee440ad6fd585704e77f50f54d3e58249", CgroupRoot: "/system.slice/ssh.service"},
		&audit.Message{Type: 1309, Data: `argc=3 a0="ls" a1="--color=auto" a2="-alF"`},
		&audit.Message{Type: 1307, Data: `cwd="/home/ubuntu"`},
		&audit.Message{Type: 1302, Data: `item=0 name="/bin/ls" inode=262316 dev=ca:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL`},
		&audit.Message{Type: 1327, Data: `proctitle=6C73002D2D636F6C6F723D6175746F002D616C46`},
	)
}

func TestBuildExecve(t *testing.T) {
	b := testBuilder(Options{Host: "web-1", Tags: map[string]string{"env": "prod"}})

	got, err := json.Marshal(b.Build(lsGroup()))
	require.NoError(t, err)

	want := `{
		"time": "2016-03-30T22:27:46.885Z",
		"sequence": 1222763,
		"host": "web-1",
		"tags": {"env": "prod"},
		"key": "user-commands",
		"syscall": {"nr": 59, "name": "execve", "arch": "x86_64", "success": true, "exit": 0},
		"process": {
			"pid": 11623, "ppid": 11552, "comm": "ls", "exe": "/bin/ls", "cwd": "/home/ubuntu",
			"args": ["ls", "--color=auto", "-alF"], "title": "ls --color=auto -alF", "tty": "pts0", "session": 35
		},
		"user": {
			"auid": 1000, "auid_name": "ubuntu", "uid": 1000, "uid_name": "ubuntu",
			"euid": 1000, "euid_name": "ubuntu", "suid": 1000, "fsuid": 1000,
			"gid": 1000, "gid_name": "ubuntu", "egid": 1000, "sgid": 1000, "fsgid": 1000
		},
		"paths": [{"item": 0, "name": "/bin/ls", "inode": 262316, "dev": "ca:01", "mode": "0100755", "ouid": 0, "ogid": 0, "nametype": "NORMAL"}],
		"container": {"id": "5c69ff1a4edf85228df5153f36cacbdee440ad6fd585704e77f50f54d3e58249"},
		"cgroup": "/system.slice/ssh.service",
		"records": [
			{"type": "SYSCALL", "type_id": 1300, "fields": {
				"arch": "c000003e", "syscall": "59", "success": "yes", "exit": "0",
				"a0": "cc4e68", "a1": "d10bc8", "a2": "c69808", "a3": "7fff2a700900", "items": "2",
				"ppid": "11552", "pid": "11623", "auid": "1000", "uid": "1000", "gid": "1000",
				"euid": "1000", "suid": "1000", "fsuid": "1000", "egid": "1000", "sgid": "1000",
				"fsgid": "1000", "tty": "pts0", "ses": "35", "comm": "ls", "exe": "/bin/ls", "key": "user-commands"}},
			{"type": "EXECVE", "type_id": 1309, "fields": {"argc": "3", "a0": "ls", "a1": "--color=auto", "a2": "-alF"}},
			{"type": "CWD", "type_id": 1307, "fields": {"cwd": "/home/ubuntu"}},
			{"type": "PATH", "type_id": 1302, "fields": {
				"item": "0", "name": "/bin/ls", "inode": "262316", "dev": "ca:01", "mode": "0100755",
				"ouid": "0", "ogid": "0", "rdev": "00:00", "nametype": "NORMAL"}},
			{"type": "PROCTITLE", "type_id": 1327, "fields": {"proctitle": "ls --color=auto -alF"}}
		]
	}`

	assert.JSONEq(t, want, string(got))
}

func TestBuildUnsetAndNullValues(t *testing.T) {
	b := testBuilder(Options{})
	ev := b.Build(group(1, "1.5",
		&audit.Message{Type: 1300, Data: `arch=c000003e syscall=42 success=no exit=-115 pid=1 auid=4294967295 uid=0 ses=4294967295 tty=(none) key=(null)`},
		&audit.Message{Type: 1302, Data: `item=0 name=(null) inode=1`},
	))

	assert.Empty(t, ev.Key)
	assert.Empty(t, ev.Host)
	assert.Nil(t, ev.Tags)
	assert.Equal(t, "connect", ev.Syscall.Name)
	assert.False(t, *ev.Syscall.Success)
	assert.Equal(t, int64(-115), *ev.Syscall.Exit)
	assert.Empty(t, ev.Process.TTY)
	assert.Nil(t, ev.Process.Session)
	assert.Equal(t, uint32(4294967295), *ev.User.AUID)
	assert.Empty(t, ev.User.AUIDName)
	assert.Equal(t, "root", ev.User.UIDName)
	assert.Empty(t, ev.Paths[0].Name)
	assert.Equal(t, "1970-01-01T00:00:01.500Z", ev.Time)
}

func TestBuildRawAndNonSyscallEvents(t *testing.T) {
	b := testBuilder(Options{Raw: true})
	ev := b.Build(group(7, "100.000",
		&audit.Message{Type: 1305, Data: `auid=1000 ses=2 op=add_rule key="x" list=4 res=1`},
	))

	assert.Nil(t, ev.Syscall)
	assert.Nil(t, ev.Process)
	assert.Nil(t, ev.User)
	require.Len(t, ev.Records, 1)
	assert.Equal(t, "CONFIG_CHANGE", ev.Records[0].Type)
	assert.Equal(t, "add_rule", ev.Records[0].Fields["op"])
	assert.Equal(t, `auid=1000 ses=2 op=add_rule key="x" list=4 res=1`, ev.Records[0].Raw)
}

func TestBuildLongExecveArgs(t *testing.T) {
	b := testBuilder(Options{})
	ev := b.Build(group(1, "1.0",
		&audit.Message{Type: 1300, Data: `arch=c00000b7 syscall=221 success=yes exit=0 pid=5`},
		&audit.Message{Type: 1309, Data: `argc=4 a0="sh" a1="-c" a2_len=10 a2[0]=6563686F20 a2[1]="hello"`},
		// The kernel continues a long argv in another EXECVE record
		&audit.Message{Type: 1309, Data: `a3=612062`},
	))

	assert.Equal(t, "execve", ev.Syscall.Name)
	assert.Equal(t, "aarch64", ev.Syscall.Arch)
	assert.Equal(t, []string{"sh", "-c", "echo hello", "a b"}, ev.Process.Args)
}

func TestBuildUnknownArch(t *testing.T) {
	ev := testBuilder(Options{}).Build(group(1, "1.0",
		&audit.Message{Type: 1300, Data: `arch=80000016 syscall=11 success=yes`},
	))

	assert.Equal(t, "80000016", ev.Syscall.Arch)
	assert.Empty(t, ev.Syscall.Name)
	assert.Equal(t, 11, *ev.Syscall.Nr)
}

func TestParseSockaddr(t *testing.T) {
	tests := []struct {
		saddr string
		want  *Network
	}{
		{"0200005070D9F00F0000000000000000", &Network{Family: "inet", Address: "112.217.240.15", Port: new(80)}},
		{"0A0001BB000000002A00145040070809000000000000200E00000000", &Network{Family: "inet6", Address: "2a00:1450:4007:809::200e", Port: new(443)}},
		{"0A00003500000000" + "00000000000000000000FFFF7F000001" + "00000000", &Network{Family: "inet6", Address: "127.0.0.1", Port: new(53)}},
		{"01002F72756E2F73797374656D642F6A6F75726E616C2F736F636B657400", &Network{Family: "unix", Path: "/run/systemd/journal/socket"}},
		{"0100006162737472616374", &Network{Family: "unix", Path: "@abstract"}},
		{"100000000000000000000000", &Network{Family: "netlink"}},
		{"2600", &Network{Family: "38"}},
		{"02000050", &Network{Family: "inet"}},
		{"zz", nil},
		{"", nil},
	}

	for _, tt := range tests {
		t.Run(tt.saddr, func(t *testing.T) {
			assert.Equal(t, tt.want, parseSockaddr(tt.saddr))
		})
	}
}

func TestBuildNetwork(t *testing.T) {
	ev := testBuilder(Options{}).Build(group(1, "1.0",
		&audit.Message{Type: 1300, Data: `arch=c000003e syscall=42 success=yes exit=0 pid=5`},
		&audit.Message{Type: 1306, Data: `saddr=020001BB0A0000050000000000000000`},
	))

	assert.Equal(t, &Network{Family: "inet", Address: "10.0.0.5", Port: new(443)}, ev.Network)
}

func TestFormatTime(t *testing.T) {
	assert.Equal(t, "2016-03-30T22:27:46.885Z", formatTime("1459376866.885"))
	assert.Equal(t, "2016-03-30T22:27:46.000Z", formatTime("1459376866"))
	assert.Equal(t, "2016-03-30T22:27:46.123Z", formatTime("1459376866.123456"))
	assert.Equal(t, "garbage", formatTime("garbage"))
	assert.Equal(t, "1.x", formatTime("1.x"))
}

func TestNameCache(t *testing.T) {
	calls := 0
	c := fakeNames(map[string]string{"0": "root"})
	lookup := c.lookup
	c.lookup = func(id string) (string, error) {
		calls++

		return lookup(id)
	}

	assert.Equal(t, "root", c.name("0"))
	assert.Empty(t, c.name("12345"))
	assert.Equal(t, "root", c.name("0"))
	assert.Empty(t, c.name("12345"))
	assert.Empty(t, c.name(unsetID))
	assert.Empty(t, c.name(""))
	assert.Equal(t, 2, calls, "results should be cached and unset ids not looked up")
}

func TestSystemNames(t *testing.T) {
	assert.Equal(t, "root", newUserCache().name("0"))
	assert.Equal(t, "root", newGroupCache().name("0"))
}

type captureEncoder struct{ got []any }

func (c *captureEncoder) Write(v any) error {
	c.got = append(c.got, v)

	return nil
}

func TestWriter(t *testing.T) {
	enc := &captureEncoder{}
	w := NewWriter(testBuilder(Options{}), enc)

	require.NoError(t, w.Write(lsGroup()))
	require.Len(t, enc.got, 1)
	assert.Equal(t, 1222763, enc.got[0].(*Event).Sequence)
}

func BenchmarkBuild(b *testing.B) {
	builder := testBuilder(Options{Host: "web-1"})
	for b.Loop() {
		_, _ = json.Marshal(builder.Build(lsGroup()))
	}
}
