package extras

import (
	"log/slog"

	"github.com/yousysadmin/go-audit/internal/audit"
	"github.com/yousysadmin/go-audit/internal/config"
)

func init() {
	register(func(cfg config.Extras, log *slog.Logger) (audit.ExtraParser, error) {
		if !cfg.Containers.Enabled {
			return nil, nil
		}

		cp := NewContainerParser(cfg.Containers)
		log.Info("container parser enabled", "pid_cache", cp.pidCache.Size())

		return cp, nil
	})
}

// ContainerParser adds the id of the container running the process to a message.
// The id is read from the process cgroup path, no container runtime is queried.
type ContainerParser struct {
	pidCache cache[int, string]
}

// NewContainerParser returns a parser caching up to cfg.PidCache pid lookups.
func NewContainerParser(cfg config.Containers) *ContainerParser {
	return &ContainerParser{pidCache: newCache[int, string](cfg.PidCache)}
}

// Parse sets ContainerID on syscall and seccomp records.
func (c *ContainerParser) Parse(am *audit.Message) {
	switch am.Type {
	case audit.TypeSyscall, audit.TypeSeccomp:
		am.ContainerID = c.containerForPid(pids(am))
	}
}

func (c *ContainerParser) containerForPid(pid, ppid int) string {
	if pid == 0 {
		return ""
	}

	cid, err := c.pidContainerID(pid)
	if err != nil {
		// The pid may have exited before we could check it, try the ppid
		return c.containerForPid(ppid, 0)
	}

	return cid
}

func (c *ContainerParser) pidContainerID(pid int) (string, error) {
	if cid, ok := c.pidCache.Get(pid); ok {
		return cid, nil
	}

	cid, err := processContainerID(pid)
	if err == nil {
		c.pidCache.Add(pid, cid)
	}

	return cid, err
}

// processContainerID returns the container id of pid, "" outside a container.
// From capsule8, see capsule8.go for the license.
func processContainerID(pid int) (string, error) {
	cgroups, err := taskControlGroups(pid, pid)
	if err != nil {
		return "", err
	}

	for _, cg := range cgroups {
		if id := containerID(cg.Path); id != "" {
			return id, nil
		}
	}

	return "", nil
}
