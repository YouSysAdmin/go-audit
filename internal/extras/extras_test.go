package extras

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yousysadmin/go-audit/internal/audit"
	"github.com/yousysadmin/go-audit/internal/config"
)

func TestPids(t *testing.T) {
	tests := []struct {
		data      string
		pid, ppid int
	}{
		{"arch=c0000000 syscall=59 success=yes exit=0 a0=1600000 items=2 ppid=30296 pid=31475 auid=4294967295 uid=0 tty=pts0 ses=4294967295 comm=\"date\" exe=\"/bin/date\" key=(null)", 31475, 30296},
		{"pid=31475 foo=bar ppid=30296", 31475, 30296},
		{"pid=31475 foo=bar", 31475, 0},
		{"pid=notanumber ppid=1", 0, 1},
		{"nothing here", 0, 0},
	}

	for _, tt := range tests {
		pid, ppid := pids(&audit.Message{Type: audit.TypeSyscall, Data: tt.data})
		assert.Equal(t, tt.pid, pid, tt.data)
		assert.Equal(t, tt.ppid, ppid, tt.data)
	}
}

func TestContainerID(t *testing.T) {
	assert.Equal(t,
		"5c69ff1a4edf85228df5153f36cacbdee440ad6fd585704e77f50f54d3e58249",
		containerID("/docker/5c69ff1a4edf85228df5153f36cacbdee440ad6fd585704e77f50f54d3e58249"),
	)
	assert.Equal(t,
		"2ce19d7466dbb3eb7b7493be01b6d3353c990e6722258e94fac8016baeefd6c8",
		containerID("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podd12649dc_490b_4e0c_b6fe_9e2fbf4a058c.slice/cri-containerd-2ce19d7466dbb3eb7b7493be01b6d3353c990e6722258e94fac8016baeefd6c8.scope"),
	)
	assert.Equal(t,
		"d84f26ddf627f6fde170d83478b4ae9d5baaaa645e484b755a46844f3da785c6",
		containerID("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podec04832a_309d_4044_9f92_7fac604a2384.slice/docker-d84f26ddf627f6fde170d83478b4ae9d5baaaa645e484b755a46844f3da785c6.scope"),
	)
	assert.Equal(t,
		"d84f26ddf627f6fde170d83478b4ae9d5baaaa645e484b755a46844f3da785c6",
		containerID("/system.slice/d84f26ddf627f6fde170d83478b4ae9d5baaaa645e484b755a46844f3da785c6.scope"),
	)
	assert.Empty(t, containerID("/user.slice/user-1000.slice/session-1.scope"))

	// Segments that are just over the hash length must not panic
	assert.Empty(t, containerID("/system.slice/"+strings.Repeat("x", 60)+".scope"))
}

func TestCgroupRootForSelf(t *testing.T) {
	if _, err := os.Stat("/proc/self/cgroup"); err != nil {
		t.Skip("no procfs")
	}

	assert.NotEmpty(t, cgroupRootForPid(os.Getpid()))
	assert.Empty(t, cgroupRootForPid(0))
}

func TestCgroupParser(t *testing.T) {
	if _, err := os.Stat("/proc/self/cgroup"); err != nil {
		t.Skip("no procfs")
	}

	p := &CgroupParser{}

	am := &audit.Message{Type: audit.TypeSyscall, Data: "pid=" + strconv.Itoa(os.Getpid())}
	p.Parse(am)
	assert.NotEmpty(t, am.CgroupRoot)

	am = &audit.Message{Type: audit.TypeCwd, Data: "pid=" + strconv.Itoa(os.Getpid())}
	p.Parse(am)
	assert.Empty(t, am.CgroupRoot, "cwd records are not enriched")
}

func TestNewSkipsDisabledParsers(t *testing.T) {
	parsers, err := New(config.Extras{}, discard)
	assert.NoError(t, err)
	assert.Empty(t, parsers)

	parsers, err = New(config.Extras{Cgroups: config.Cgroups{Enabled: true}}, discard)
	assert.NoError(t, err)
	assert.Len(t, parsers, 1)
}

func TestLRU(t *testing.T) {
	c := newCache[int, string](2)
	c.Add(1, "a")
	c.Add(2, "b")

	_, _ = c.Get(1) // 1 is now most recent
	c.Add(3, "c")   // evicts 2

	_, ok := c.Get(2)
	assert.False(t, ok)

	v, ok := c.Get(1)
	assert.True(t, ok)
	assert.Equal(t, "a", v)

	c.Add(1, "z")
	v, _ = c.Get(1)
	assert.Equal(t, "z", v)
	assert.Equal(t, 2, c.Size())

	off := newCache[int, string](0)
	off.Add(1, "a")
	_, ok = off.Get(1)
	assert.False(t, ok)
	assert.Equal(t, 0, off.Size())
}

var discard = slog.New(slog.DiscardHandler)

func TestContainerParser(t *testing.T) {
	parsers, err := New(config.Extras{
		Cgroups:    config.Cgroups{Enabled: true},
		Containers: config.Containers{Enabled: true, PidCache: 4},
	}, discard)
	require.NoError(t, err)
	assert.Len(t, parsers, 2)

	p := NewContainerParser(config.Containers{PidCache: 4})

	// No pid, nothing to look up
	am := &audit.Message{Type: audit.TypeSyscall, Data: "arch=c000003e syscall=59"}
	p.Parse(am)
	assert.Empty(t, am.ContainerID)

	// Other record types are not enriched
	am = &audit.Message{Type: audit.TypeCwd, Data: "pid=1"}
	p.Parse(am)
	assert.Empty(t, am.ContainerID)

	// A cached container id is used without reading procfs
	p.pidCache.Add(424242, "5c69ff1a4edf85228df5153f36cacbdee440ad6fd585704e77f50f54d3e58249")
	am = &audit.Message{Type: audit.TypeSyscall, Data: "ppid=1 pid=424242"}
	p.Parse(am)
	assert.Equal(t, "5c69ff1a4edf85228df5153f36cacbdee440ad6fd585704e77f50f54d3e58249", am.ContainerID)
}
