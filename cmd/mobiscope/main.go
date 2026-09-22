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
		Use:   "mobiscope",
		Short: "Static analysis harness for APK files",
		Long:  "mobiscope orchestrates external tools and LLMs to analyze Android APKs.",
	}

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

// loadConfigWithFlags loads config and applies global flags.
func loadConfigWithFlags() (*config.Config, error) {
	cfg, err := config.Load(context.Background(), "")
	if err != nil {
		return nil, err
	}
	if globalFlags.AllowCloud {
		cfg.LLM.AllowCloud = true
	}
	return cfg, nil
}
