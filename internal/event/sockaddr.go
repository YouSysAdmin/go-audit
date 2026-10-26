package event

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// Address families as found in the first two bytes of saddr, host byte order.
const (
	afUnix    = 1
	afInet    = 2
	afInet6   = 10
	afNetlink = 16
)

// parseSockaddr decodes the hex saddr field of a SOCKADDR record.
func parseSockaddr(saddr string) *Network {
	b, err := hex.DecodeString(saddr)
	if err != nil || len(b) < 2 {
		return nil
	}

	family := binary.NativeEndian.Uint16(b)

	switch family {
	case afUnix:
		// An abstract socket name starts with a NUL, shown with a leading @ like ss does
		path := b[2:]
		abstract := len(path) > 0 && path[0] == 0
		if abstract {
			path = path[1:]
		}

		p := strings.TrimRight(string(path), "\x00")
		if i := strings.IndexByte(p, 0); i >= 0 {
			p = p[:i]
		}

		if abstract {
			p = "@" + p
		}

		return &Network{Family: "unix", Path: p}
	case afInet:
		// family(2) port(2, big endian) address(4)
		if len(b) < 8 {
			return &Network{Family: "inet"}
		}

		addr := netip.AddrFrom4([4]byte(b[4:8]))

		return &Network{Family: "inet", Address: addr.String(), Port: new(int(binary.BigEndian.Uint16(b[2:4])))}
	case afInet6:
		// family(2) port(2, big endian) flowinfo(4) address(16)
		if len(b) < 24 {
			return &Network{Family: "inet6"}
		}

		// IPv4 mapped addresses (::ffff:a.b.c.d) are shown as IPv4
		addr := netip.AddrFrom16([16]byte(b[8:24])).Unmap()

		return &Network{Family: "inet6", Address: addr.String(), Port: new(int(binary.BigEndian.Uint16(b[2:4])))}
	case afNetlink:
		return &Network{Family: "netlink"}
	default:
		return &Network{Family: strconv.Itoa(int(family))}
	}
}
