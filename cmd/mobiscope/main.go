package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/dedek0/mobiscope/internal/config"
	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/spf13/cobra"
)

// Exit codes.
const (
	ExitOK              = 0
	ExitError           = 1
	ExitProviderBlocked = 4
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

// GlobalFlags holds flags available on all commands.
type GlobalFlags struct {
	Config     string
	Provider   string
	AllowCloud bool
}

var globalFlags GlobalFlags

func main() {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(classifyExit(err))
	}
}

func classifyExit(err error) int {
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, llm.ErrCloudNotAllowed) || errors.Is(err, llm.ErrProviderUnavailable) {
		return ExitProviderBlocked
	}
	return ExitError
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "mobiscope",
		Short:         "Static analysis harness for APK files",
		Long:          "mobiscope orchestrates external tools and LLMs to analyze Android APKs.",
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	cmd.PersistentFlags().StringVar(&globalFlags.Config, "config", "", "Config file (TOML). Default: $MOBISCOPE_CONFIG or ./config.toml")
	cmd.PersistentFlags().StringVar(&globalFlags.Provider, "provider", "", "Override LLM provider for all tasks")
	cmd.PersistentFlags().BoolVar(&globalFlags.AllowCloud, "allow-cloud", false, "Allow cloud LLM providers")

	cmd.AddCommand(newVersionCmd())
	cmd.AddCommand(newAnalyzeCmd())
	cmd.AddCommand(newLLMCmd())
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("mobiscope %s (commit: %s, built: %s)\n", version, commit, buildTime)
		},
	}
}

// loadConfigWithFlags loads config with the standard precedence
// (defaults < file < env < flags) and returns the effective configuration.
func loadConfigWithFlags(cmd *cobra.Command) (*config.Config, error) {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return config.Load(ctx, globalFlags.Config, cmd.Flags())
}
