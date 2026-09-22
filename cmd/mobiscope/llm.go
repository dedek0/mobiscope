package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/dedek0/mobiscope/internal/llm/providers/ollama"
	"github.com/spf13/cobra"
)

func newLLMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "llm",
		Short: "LLM provider management",
		Long:  "Manage LLM providers: health, detection, models, testing, and configuration.",
	}
	cmd.AddCommand(newLLMHealthCmd())
	cmd.AddCommand(newLLMListCmd())
	cmd.AddCommand(newLLMPullCmd())
	cmd.AddCommand(newLLMDetectCmd())
	cmd.AddCommand(newLLMConfigCmd())
	cmd.AddCommand(newLLMTestCmd())
	cmd.AddCommand(newLLMModelsCmd())
	return cmd
}

// --- llm health ---

func newLLMHealthCmd() *cobra.Command {
	var providerName string

	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check LLM provider health",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := loadConfigWithFlags()
			if err != nil {
				return err
			}

			factory := llm.NewFactory(slogDefault())
			providers, err := factory.CreateAll(cfg.LLM.Providers)
			if err != nil {
				return fmt.Errorf("creating providers: %w", err)
			}

			if providerName != "" {
				return checkOneHealth(c.Context(), providers, providerName)
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "PROVIDER\tSTATUS\tKIND\n")
			for name, p := range providers {
				status := "unavailable"
				if p.IsAvailable(c.Context()) {
					status = "ok"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", name, status, p.Kind())
			}
			return w.Flush()
		},
	}

	cmd.Flags().StringVar(&providerName, "provider", "", "Check specific provider")
	return cmd
}

func checkOneHealth(ctx context.Context, providers map[string]llm.Provider, name string) error {
	p, ok := providers[name]
	if !ok {
		return fmt.Errorf("provider %q not configured", name)
	}
	if p.IsAvailable(ctx) {
		fmt.Printf("%s: ok (%s)\n", name, p.Kind())
		return nil
	}
	fmt.Printf("%s: unavailable\n", name)
	return nil
}

// --- llm list ---

func newLLMListCmd() *cobra.Command {
	var providerName string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List models from providers",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := loadConfigWithFlags()
			if err != nil {
				return err
			}

			factory := llm.NewFactory(slogDefault())
			providers, err := factory.CreateAll(cfg.LLM.Providers)
			if err != nil {
				return fmt.Errorf("creating providers: %w", err)
			}

			if providerName != "" {
				return listModelsProvider(c.Context(), providers, providerName)
			}

			for name := range providers {
				if err := listModelsProvider(c.Context(), providers, name); err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&providerName, "provider", "", "List models from specific provider")
	return cmd
}

func listModelsProvider(ctx context.Context, providers map[string]llm.Provider, name string) error {
	p, ok := providers[name]
	if !ok {
		return fmt.Errorf("provider %q not configured", name)
	}

	models, err := p.Models(ctx)
	if err != nil {
		return fmt.Errorf("listing models for %s: %w", name, err)
	}

	fmt.Printf("[%s] (%s)\n", name, p.Kind())
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  NAME\tSIZE\tMODIFIED\n")
	for _, m := range models {
		fmt.Fprintf(w, "  %s\t%s\t%s\n", m.Name, formatSize(m.Size), m.Modified)
	}
	return w.Flush()
}

// --- llm pull ---

func newLLMPullCmd() *cobra.Command {
	var providerName string

	cmd := &cobra.Command{
		Use:   "pull <model>",
		Short: "Pull/download a model",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			model := args[0]

			if providerName == "" {
				providerName = "ollama"
			}

			cfg, err := loadConfigWithFlags()
			if err != nil {
				return err
			}

			factory := llm.NewFactory(slogDefault())
			providers, err := factory.CreateAll(cfg.LLM.Providers)
			if err != nil {
				return fmt.Errorf("creating providers: %w", err)
			}

			p, ok := providers[providerName]
			if !ok {
				return fmt.Errorf("provider %q not configured", providerName)
			}

			if providerName == "ollama" {
				if ollamaProv, ok := p.(*ollama.Provider); ok {
					fmt.Fprintf(os.Stderr, "Pulling %s from %s...\n", model, providerName)
					if err := ollamaProv.Pull(c.Context(), model); err != nil {
						return fmt.Errorf("pulling model: %w", err)
					}
					fmt.Fprintf(os.Stderr, "Done.\n")
					return nil
				}
			}

			return fmt.Errorf("pull is only supported for the ollama provider")
		},
	}

	cmd.Flags().StringVar(&providerName, "provider", "ollama", "Provider to pull from")
	return cmd
}

// --- llm detect ---

func newLLMDetectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "detect",
		Short: "Detect available LLM providers",
		Long:  "Probe local endpoints and check env vars to discover available providers.",
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := loadConfigWithFlags()
			if err != nil {
				return err
			}

			factory := llm.NewFactory(slogDefault())
			providers, err := factory.CreateAll(cfg.LLM.Providers)
			if err != nil {
				return fmt.Errorf("creating providers: %w", err)
			}

			detector := llm.NewDetector(slogDefault())
			results := detector.DetectAvailable(c.Context(), providers)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "PROVIDER\tTYPE\tSTATUS\tLATENCY\tSOURCE\tMODELS\n")
			for _, r := range results {
				status := "\033[31munavailable\033[0m"
				if r.Available {
					status = "\033[32mavailable\033[0m"
				}
				kind := r.Kind.String()
				latency := "-"
				if r.Latency > 0 {
					latency = fmt.Sprintf("%dms", r.Latency)
				}
				models := "-"
				if len(r.Models) > 0 {
					models = fmt.Sprintf("%d model(s)", len(r.Models))
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, kind, status, latency, r.Source, models)
			}
			return w.Flush()
		},
	}
}

// --- llm config ---

func newLLMConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Show effective LLM configuration",
		Long:  "Display the resolved provider/model for each task.",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := loadConfigWithFlags()
			if err != nil {
				return err
			}

			fmt.Printf("Default provider:    %s\n", cfg.LLM.DefaultProvider)
			fmt.Printf("Allow cloud:         %v\n", cfg.LLM.AllowCloud)
			fmt.Printf("Allow cloud secrets: %v\n\n", cfg.LLM.AllowCloudSecrets)

			tasks := make([]string, 0, len(cfg.LLM.Tasks))
			for k := range cfg.LLM.Tasks {
				tasks = append(tasks, k)
			}
			sort.Strings(tasks)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "TASK\tPROVIDER\tMODEL\n")
			for _, task := range tasks {
				t := cfg.LLM.Tasks[task]
				fmt.Fprintf(w, "%s\t%s\t%s\n", task, t.Provider, t.Model)
			}
			return w.Flush()
		},
	}
}

// --- llm test ---

func newLLMTestCmd() *cobra.Command {
	var taskName string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Send a test prompt to verify provider connectivity",
		Long:  "Sends a minimal prompt to the configured provider for a task and displays the response.",
		RunE: func(c *cobra.Command, _ []string) error {
			if taskName == "" {
				taskName = "triage"
			}

			cfg, err := loadConfigWithFlags()
			if err != nil {
				return err
			}

			factory := llm.NewFactory(slogDefault())
			providers, err := factory.CreateAll(cfg.LLM.Providers)
			if err != nil {
				return fmt.Errorf("creating providers: %w", err)
			}

			router := llm.NewRouter(providers, cfg.LLM, slogDefault())

			task := llmtypes.TaskType(taskName)
			route, err := router.Route(c.Context(), task, false)
			if err != nil {
				return fmt.Errorf("routing failed: %w", err)
			}

			fmt.Printf("Provider: %s (%s)\n", route.Provider.Name(), route.Provider.Kind())
			fmt.Printf("Model:    %s\n", route.Model)
			fmt.Printf("Task:     %s\n\n", route.TaskName)

			prompt := "Respond with exactly: {\"status\":\"ok\"}"
			req := llmtypes.ChatRequest{
				Model: route.Model,
				Messages: []llmtypes.Message{
					{Role: "user", Content: prompt},
				},
				JSONMode: route.Provider.Capabilities().JSONMode,
			}

			start := time.Now()
			resp, err := route.Provider.Chat(c.Context(), req)
			elapsed := time.Since(start)

			if err != nil {
				return fmt.Errorf("chat failed: %w", err)
			}

			cost := llm.EstimateCost(route.Model, resp.Usage)

			fmt.Printf("Response (%s):\n%s\n\n", elapsed.Round(time.Millisecond), resp.Content)
			fmt.Printf("Tokens:   %d in / %d out\n", resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
			fmt.Printf("Cost:     $%.6f\n", cost)

			return nil
		},
	}

	cmd.Flags().StringVar(&taskName, "task", "triage", "Task to test (triage, chat, remediation, correlate)")
	return cmd
}

// --- llm models ---

func newLLMModelsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "models",
		Short: "List known models with pricing",
		Long:  "Display all models in the price table with their cost per 1K tokens.",
		Run: func(_ *cobra.Command, _ []string) {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "MODEL\tINPUT/1K\tOUTPUT/1K\tLOCAL\n")

			models := make([]string, 0, len(llm.PriceTable))
			for m := range llm.PriceTable {
				models = append(models, m)
			}
			sort.Strings(models)

			for _, m := range models {
				price := llm.PriceTable[m]
				local := "no"
				if price.Per1KInput == 0 && price.Per1KOutput == 0 {
					local = "yes"
				}
				fmt.Fprintf(w, "%s\t$%.4f\t$%.4f\t%s\n", m, price.Per1KInput, price.Per1KOutput, local)
			}
			w.Flush()
		},
	}
}

// --- helpers ---

func formatSize(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	case bytes > 0:
		return fmt.Sprintf("%d B", bytes)
	default:
		return "-"
	}
}
