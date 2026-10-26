package extras

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// controlGroup is one line of /proc/<pid>/task/<tid>/cgroup.
type controlGroup struct {
	// Hierarchy id, 0 for cgroup v2
	ID int

	// Controllers bound to the hierarchy, empty for cgroup v2
	Controllers []string

	// Path of the group relative to the hierarchy mount point
	Path string
}

// taskControlGroups returns the cgroups of a task, malformed lines are skipped.
func taskControlGroups(tgid, pid int) ([]controlGroup, error) {
	filename := fmt.Sprintf("/proc/%d/task/%d/cgroup", tgid, pid)
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cgroups []controlGroup

	for line := range strings.Lines(string(data)) {
		parts := strings.SplitN(strings.TrimRight(line, "\n"), ":", 3)
		if len(parts) != 3 {
			continue
		}

		var ID int
		ID, err = strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		c := controlGroup{
			ID:          ID,
			Controllers: strings.Split(parts[1], ","),
			Path:        parts[2],
		}

		cgroups = append(cgroups, c)
	}

	return cgroups, nil
}

func isHexDigit(r rune) bool {
	if r >= '0' && r <= '9' {
		return true
	}
	if r >= 'A' && r <= 'F' {
		return true
	}
	if r >= 'a' && r <= 'f' {
		return true
	}
	return false
}

// sha256HexSize is the length of a hex encoded sha256, the form of a container id.
const sha256HexSize = sha256.Size * 2

func isSHA256(s string) bool {
	if len(s) != sha256HexSize {
		return false
	}
	for _, c := range s {
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// containerID returns the container id in a cgroup path, "" when there is none.
// Runtimes name the path differently (/docker/<id>, cri-containerd-<id>.scope,
// docker-<id>.scope), so any path segment that is, starts with or ends with a
// sha256 is taken as the id.
func containerID(s string) string {
	paths := strings.SplitSeq(s, "/")
	for p := range paths {
		if isSHA256(p) {
			return p
		}
		if len(p) > sha256HexSize {
			// Does it start with a sha256?
			x := p[:sha256HexSize]
			if !isHexDigit(rune(p[sha256HexSize])) && isSHA256(x) {
				return x
			}
			// Does it end with a sha256?
			p = strings.TrimSuffix(p, ".scope")
			if len(p) <= sha256HexSize {
				if isSHA256(p) {
					return p
				}

				continue
			}

			x = p[len(p)-sha256HexSize:]
			if !isHexDigit(rune(p[len(p)-sha256HexSize-1])) && isSHA256(x) {
				return x
			}
		}
	}
	return ""
}
