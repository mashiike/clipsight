package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/mashiike/clipsight"
	"golang.org/x/exp/slog"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer cancel()
	if err := clipsight.RunCLI(ctx, os.Args[1:]); err != nil {
		slog.Error("failed execution", "detail", err)
		os.Exit(1)
	}
}
