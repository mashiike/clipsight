package clipsight

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/fatih/color"
	"github.com/fujiwara/logutils"
)

type CLI struct {
	LogLevel       string          `help:"output log level" env:"CLIPSIGHT_LOG_LEVEL" default:"info"`
	DDBTable       string          `help:"DynamoDB table name for user infomation" env:"CLIPSIGHT_DDB_TABLE" default:"clipsight"`
	PermissionFile string          `help:"Permission file path" env:"CLIPSIGHT_PERMISSION_FILE" default:""`
	SopsEncryped   bool            `help:"Permission file is encrypted by sops" env:"CLIPSIGHT_SOPS_ENCRYPTED" default:"false"`
	Register       *RegisterOption `cmd:"" help:"Register user"`
	Grant          *GrantOption    `cmd:"" help:"grant dashboard view auth to user"`
	Revoke         *RevokeOption   `cmd:"" help:"revoke dashboard view auth from user"`
	Serve          *ServeOption    `cmd:"" help:"Start a ClipSight server" default:"withargs"`
	Version        struct{}        `cmd:"" help:"Show version"`
}

func RunCLI(ctx context.Context, args []string) error {
	var cli CLI
	parser, err := kong.New(&cli, kong.Vars{"version": Version})
	if err != nil {
		return err
	}
	kctx, err := parser.Parse(args)
	if err != nil {
		return err
	}
	filter := &logutils.LevelFilter{
		Levels: []logutils.LogLevel{"debug", "info", "notice", "warn", "error"},
		ModifierFuncs: []logutils.ModifierFunc{
			logutils.Color(color.FgHiBlack),
			nil,
			logutils.Color(color.FgHiBlue),
			logutils.Color(color.FgYellow),
			logutils.Color(color.FgRed, color.BgBlack),
		},
		MinLevel: logutils.LogLevel(cli.LogLevel),
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)
	app, err := New(ctx, &cli)
	if err != nil {
		return err
	}
	cmd := strings.Fields(kctx.Command())[0]
	return app.Dispatch(ctx, cmd, &cli)
}

func (app *ClipSight) Dispatch(ctx context.Context, command string, cli *CLI) error {
	if command != "version" {
		if app.isDDBMode() {
			if err := app.prepareDynamoDB(ctx); err != nil {
				return err
			}
		}
	}
	switch command {
	case "register":
		return app.RunRegister(ctx, cli.Register)
	case "grant":
		return app.RunGrant(ctx, cli.Grant)
	case "serve":
		return app.RunServe(ctx, cli.Serve)
	case "revoke":
		return app.RunRevoke(ctx, cli.Revoke)
	case "version":
		fmt.Printf("clipsight %s\n", Version)
		return nil
	}
	return fmt.Errorf("unknown command: %s", command)
}
