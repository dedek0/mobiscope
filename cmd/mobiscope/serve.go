package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dedek0/mobiscope/internal/api"
	"github.com/spf13/cobra"
)

// defaultServeAddr binds loopback only. The API has no authentication by
// default; exposing it on a network interface is a security risk.
const defaultServeAddr = "127.0.0.1:8080"

func newServeCmd() *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP API server",
		Long: `Start the mobiscope HTTP API.

By default the server listens on 127.0.0.1 (loopback only) and has no
authentication. Exposing it beyond loopback allows anyone who can reach the
port to trigger LLM calls and model downloads. Set MOBISCOPE_API_TOKEN to
enable bearer-token authentication before binding to a non-loopback address.`,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := loadConfigWithFlags(c)
			if err != nil {
				return err
			}

			srv, err := api.NewServer(cfg, slogDefault())
			if err != nil {
				return fmt.Errorf("creating api server: %w", err)
			}

			httpSrv := &http.Server{
				Addr:              addr,
				Handler:           srv.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       60 * time.Second,
				WriteTimeout:      120 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			errCh := make(chan error, 1)
			go func() {
				slogDefault().Info("http api listening",
					"addr", addr,
					"auth", os.Getenv("MOBISCOPE_API_TOKEN") != "",
				)
				if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
				close(errCh)
			}()

			select {
			case err := <-errCh:
				return err
			case <-ctx.Done():
				slogDefault().Info("shutting down")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				if err := httpSrv.Shutdown(shutdownCtx); err != nil {
					return fmt.Errorf("shutdown: %w", err)
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&addr, "addr", defaultServeAddr, "Listen address (keep 127.0.0.1 unless you understand the risk)")
	return cmd
}
