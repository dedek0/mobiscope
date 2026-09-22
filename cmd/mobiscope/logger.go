package main

import "log/slog"

func slogDefault() *slog.Logger {
	return slog.Default()
}
