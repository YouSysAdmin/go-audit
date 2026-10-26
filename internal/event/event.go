// Package event builds the JSON document written for each audit event.
package event

// Event is one audit event, every record sharing one sequence number.
// Sections are omitted when the event has no record they come from.
type Event struct {
	Time      string            `json:"time"`
	Sequence  int               `json:"sequence"`
	Host      string            `json:"host,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	Key       string            `json:"key,omitempty"`
	Syscall   *Syscall          `json:"syscall,omitempty"`
	Process   *Process          `json:"process,omitempty"`
	User      *User             `json:"user,omitempty"`
	Paths     []Path            `json:"paths,omitempty"`
	Network   *Network          `json:"network,omitempty"`
	Container *Container        `json:"container,omitempty"`
	Cgroup    string            `json:"cgroup,omitempty"`
	Records   []Record          `json:"records"`
}

// Syscall is taken from the SYSCALL record.
type Syscall struct {
	Nr      *int   `json:"nr,omitempty"`
	Name    string `json:"name,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Success *bool  `json:"success,omitempty"`
	Exit    *int64 `json:"exit,omitempty"`
}

// Process is taken from the SYSCALL, EXECVE, PROCTITLE and CWD records.
type Process struct {
	PID     *int     `json:"pid,omitempty"`
	PPID    *int     `json:"ppid,omitempty"`
	Comm    string   `json:"comm,omitempty"`
	Exe     string   `json:"exe,omitempty"`
	Cwd     string   `json:"cwd,omitempty"`
	Args    []string `json:"args,omitempty"`
	Title   string   `json:"title,omitempty"`
	TTY     string   `json:"tty,omitempty"`
	Session *uint32  `json:"session,omitempty"`
}

// User holds the ids of the SYSCALL record and the names they resolve to.
type User struct {
	AUID     *uint32 `json:"auid,omitempty"`
	AUIDName string  `json:"auid_name,omitempty"`
	UID      *uint32 `json:"uid,omitempty"`
	UIDName  string  `json:"uid_name,omitempty"`
	EUID     *uint32 `json:"euid,omitempty"`
	EUIDName string  `json:"euid_name,omitempty"`
	SUID     *uint32 `json:"suid,omitempty"`
	FSUID    *uint32 `json:"fsuid,omitempty"`
	GID      *uint32 `json:"gid,omitempty"`
	GIDName  string  `json:"gid_name,omitempty"`
	EGID     *uint32 `json:"egid,omitempty"`
	SGID     *uint32 `json:"sgid,omitempty"`
	FSGID    *uint32 `json:"fsgid,omitempty"`
}

// Path is one PATH record.
type Path struct {
	Item     *int    `json:"item,omitempty"`
	Name     string  `json:"name,omitempty"`
	Inode    *uint64 `json:"inode,omitempty"`
	Dev      string  `json:"dev,omitempty"`
	Mode     string  `json:"mode,omitempty"`
	OUID     *uint32 `json:"ouid,omitempty"`
	OGID     *uint32 `json:"ogid,omitempty"`
	Nametype string  `json:"nametype,omitempty"`
}

// Network is the decoded SOCKADDR record.
type Network struct {
	Family  string `json:"family"`
	Address string `json:"address,omitempty"`
	Port    *int   `json:"port,omitempty"`
	Path    string `json:"path,omitempty"`
}

// Container identifies the container running the process.
type Container struct {
	ID string `json:"id"`
}

// Record is one raw audit record with its parsed fields.
type Record struct {
	Type   string            `json:"type"`
	TypeID uint16            `json:"type_id"`
	Fields map[string]string `json:"fields"`
	Raw    string            `json:"raw,omitempty"`
}
