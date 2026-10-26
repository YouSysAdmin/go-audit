// Package syscalls maps audit architecture ids and syscall numbers to names.
package syscalls

import (
	"strconv"
	"strings"
)

//go:generate go run gen.go

// archNames maps the audit `arch=` value (AUDIT_ARCH_*) to a name.
var archNames = map[string]string{
	"c000003e": "x86_64",
	"40000003": "i386",
	"c00000b7": "aarch64",
	"40000028": "arm",
}

// Arch returns the architecture name for an audit arch id, or "" when unknown.
func Arch(auditArch string) string {
	return archNames[strings.ToLower(auditArch)]
}

// Name returns the syscall name for a number on an audit arch id, or "" when unknown.
func Name(auditArch string, nr int) string {
	return tables[Arch(auditArch)][nr]
}

// NameOf is Name for a decimal syscall number as found in audit records.
func NameOf(auditArch, nr string) string {
	n, err := strconv.Atoi(nr)
	if err != nil {
		return ""
	}

	return Name(auditArch, n)
}
