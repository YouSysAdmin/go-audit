// Package cli wires the cobra commands the go-audit binary exposes.
package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/yousysadmin/go-audit/pkg"
)

// NewRoot builds the root command, which runs the daemon.
//
// Errors are silenced here and printed once by main.
func NewRoot() *cobra.Command {
	var configFile string

	root := &cobra.Command{
		Use:           pkg.AppName + " --config FILE",
		Short:         "Linux audit event collector that emits JSON",
		Version:       pkg.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configFile == "" {
				return &UsageError{Err: errors.New("a config file must be provided")}
			}

			return run(cmd.Context(), configFile)
		},
	}
	root.SetFlagErrorFunc(flagError)
	root.Flags().StringVar(&configFile, "config", "", "config file location (yaml)")

	root.AddCommand(newVersionCmd())

	return root
}
