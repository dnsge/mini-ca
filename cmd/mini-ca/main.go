package main

import (
	"context"
	"fmt"
	"github.com/urfave/cli/v2"
	"os"
	"os/signal"
	"syscall"
)

func signalInterrupterContext() context.Context {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGKILL)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer func() {
			cancel()
		}()
		<-c
	}()

	return ctx
}

func main() {
	//pwd, err := os.Getwd()
	//if err != nil {
	//	panic(err)
	//}

	ctx := signalInterrupterContext()

	app := &cli.App{
		Name:  "mini-ca",
		Usage: "A small tool to help with creating certificate authorities",
		Commands: []*cli.Command{
			{
				Name:      "new",
				Usage:     "Create a new key/certificate pair",
				Action:    runNewCommand,
				ArgsUsage: "[type: root/mid/leaf]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Usage:    "The name for the key/certificate pair",
						Required: true,
					},
					&cli.StringFlag{
						Name:        "out",
						Usage:       "The output directory for the key/certificate pair",
						Value:       ".",
						DefaultText: "Current directory",
					},
					&cli.StringFlag{
						Name:  "parent",
						Usage: "The name for the parent key/certificate pair (if not self-signed)",
					},
					&cli.StringFlag{
						Name:        "in",
						Usage:       "The input directory for the parent key/certificate pair (if not self-signed)",
						Value:       ".",
						DefaultText: "Current directory",
					},
				},
			},
		},
	}

	if err := app.RunContext(ctx, os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
