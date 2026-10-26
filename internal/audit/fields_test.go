package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFields(t *testing.T) {
	tests := []struct {
		name string
		typ  uint16
		data string
		want map[string]string
	}{
		{
			name: "syscall",
			typ:  TypeSyscall,
			data: `arch=c000003e syscall=59 success=yes exit=0 a0=cc4e68 comm="ls" exe="/bin/ls" key=(null)`,
			want: map[string]string{
				"arch": "c000003e", "syscall": "59", "success": "yes", "exit": "0",
				"a0": "cc4e68", "comm": "ls", "exe": "/bin/ls", "key": "(null)",
			},
		},
		{
			name: "hex encoded strings",
			typ:  TypeSyscall,
			data: `comm=6D7920617070 exe="/usr/bin/x" key=757365722D636F6D6D616E6473`,
			want: map[string]string{"comm": "my app", "exe": "/usr/bin/x", "key": "user-commands"},
		},
		{
			name: "several rule keys",
			typ:  TypeSyscall,
			data: `key=6F6E650174776F`,
			want: map[string]string{"key": "one,two"},
		},
		{
			name: "execve arguments",
			typ:  TypeExecve,
			data: `argc=3 a0="ls" a1=2D2D636F6C6F723D6175746F2061 a2_len=8 a2[0]=2D61 a2[1]="lF"`,
			want: map[string]string{"argc": "3", "a0": "ls", "a1": "--color=auto a", "a2_len": "8", "a2[0]": "-a", "a2[1]": "lF"},
		},
		{
			name: "a0 is not hex decoded outside EXECVE",
			typ:  TypeSyscall,
			data: `a0=6c73`,
			want: map[string]string{"a0": "6c73"},
		},
		{
			name: "proctitle",
			typ:  TypeProctitle,
			data: `proctitle=6C73002D2D636F6C6F723D6175746F`,
			want: map[string]string{"proctitle": "ls --color=auto"},
		},
		{
			name: "user message",
			typ:  1112,
			data: `pid=1 uid=0 auid=1000 ses=2 msg='op=login acct="root" exe="/usr/sbin/sshd" res=success'`,
			want: map[string]string{
				"pid": "1", "uid": "0", "auid": "1000", "ses": "2",
				"op": "login", "acct": "root", "exe": "/usr/sbin/sshd", "res": "success",
			},
		},
		{
			name: "odd input",
			typ:  TypeCwd,
			data: `  cwd="/home/a b"  stray name="unterminated`,
			want: map[string]string{"cwd": "/home/a b", "name": "unterminated"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseFields(tt.typ, tt.data))
		})
	}
}

func TestMessageFieldsAreCached(t *testing.T) {
	m := &Message{Type: TypeCwd, Data: `cwd="/a"`}
	f := m.Fields()
	f["cwd"] = "changed"
	assert.Equal(t, "changed", m.Fields()["cwd"])
}

func BenchmarkParseFields(b *testing.B) {
	data := `arch=c000003e syscall=59 success=yes exit=0 a0=cc4e68 a1=d10bc8 a2=c69808 a3=7fff2a700900 items=2 ppid=11552 pid=11623 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=35 comm="ls" exe="/bin/ls" key=(null)`
	for b.Loop() {
		_ = ParseFields(TypeSyscall, data)
	}
}
