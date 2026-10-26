package extras

import (
	"strconv"

	"github.com/yousysadmin/go-audit/internal/audit"
)

// pids returns the pid and ppid of a record, 0 when absent.
func pids(am *audit.Message) (pid, ppid int) {
	f := am.Fields()
	pid, _ = strconv.Atoi(f["pid"])
	ppid, _ = strconv.Atoi(f["ppid"])

	return pid, ppid
}
