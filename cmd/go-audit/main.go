// Command go-audit reads kernel audit events over netlink and writes them as JSON.
package main

import (
	"fmt"
	"os"

	"github.com/yousysadmin/go-audit/internal/cli"
	"github.com/yousysadmin/go-audit/pkg"
)

func main() {
	err := cli.NewRoot().Execute()
	if err == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "%s: %v\n", pkg.AppName, err)
	os.Exit(cli.ExitCode(err))
}
