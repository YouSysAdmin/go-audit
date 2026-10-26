package extras

import (
	"log/slog"

	"github.com/yousysadmin/go-audit/internal/audit"
	"github.com/yousysadmin/go-audit/internal/config"
)

func init() {
	register(func(cfg config.Extras, log *slog.Logger) (audit.ExtraParser, error) {
		if !cfg.Cgroups.Enabled {
			return nil, nil
		}

		log.Info("cgroup parser enabled")

		return &CgroupParser{}, nil
	})
}

// CgroupParser adds the cgroup root of the process to a message.
type CgroupParser struct{}

// Parse sets CgroupRoot on process related records.
func (p *CgroupParser) Parse(am *audit.Message) {
	switch am.Type {
	case audit.TypeSyscall, audit.TypePath, audit.TypeExecve, audit.TypeSeccomp:
		pid, _ := pids(am)
		am.CgroupRoot = cgroupRootForPid(pid)
	}
}

// cgroupRootForPid prefers the cgroup v2 path and falls back to the v1 pids controller path.
func cgroupRootForPid(pid int) string {
	if pid == 0 {
		return ""
	}

	cgroups, err := taskControlGroups(pid, pid)
	if err != nil {
		return ""
	}

	var v1PidPath string
	for _, cgroup := range cgroups {
		if cgroup.ID == 0 {
			return cgroup.Path
		}

		if len(cgroup.Controllers) > 0 && cgroup.Controllers[0] == "pids" {
			v1PidPath = cgroup.Path
		}
	}

	return v1PidPath
}
