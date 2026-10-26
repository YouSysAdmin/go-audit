package syscalls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNames(t *testing.T) {
	tests := []struct {
		arch, nr, name string
	}{
		{"c000003e", "59", "execve"},
		{"c000003e", "42", "connect"},
		{"C000003E", "42", "connect"},
		{"c00000b7", "221", "execve"},
		{"c00000b7", "203", "connect"},
		{"40000003", "11", "execve"},
		{"40000028", "283", "connect"},
		{"c000003e", "99999", ""},
		{"c000003e", "x", ""},
		{"deadbeef", "59", ""},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.name, NameOf(tt.arch, tt.nr), "%s %s", tt.arch, tt.nr)
	}
}

func TestArch(t *testing.T) {
	assert.Equal(t, "x86_64", Arch("c000003e"))
	assert.Equal(t, "aarch64", Arch("c00000b7"))
	assert.Equal(t, "i386", Arch("40000003"))
	assert.Equal(t, "arm", Arch("40000028"))
	assert.Empty(t, Arch("80000016"))
}
