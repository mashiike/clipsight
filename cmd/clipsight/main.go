package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mashiike/clipsight"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer cancel()
	if err := clipsight.RunCLI(ctx, os.Args[1:]); err != nil {
		log.Fatalf("[error] %v", err)
	}
}
