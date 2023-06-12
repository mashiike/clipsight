package clipsight

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/fatih/color"
	"github.com/mashiike/slogutils"
	"golang.org/x/exp/slog"
)

type CLI struct {
	LogLevel  string          `help:"output log level" env:"CLIPSIGHT_LOG_LEVEL" default:"info"`
	DDBTable  string          `help:"DynamoDB table name for user infomation" env:"CLIPSIGHT_DDB_TABLE" default:"clipsight"`
	MaskEmail bool            `help:"mask email address in log"`
	Register  *RegisterOption `cmd:"" help:"Register user"`
	Grant     *GrantOption    `cmd:"" help:"grant dashboard view auth to user"`
	Revoke    *RevokeOption   `cmd:"" help:"revoke dashboard view auth from user"`
	Serve     *ServeOption    `cmd:"" help:"Start a ClipSight server" default:"withargs"`
	Plan      *PlanOption     `cmd:"" help:"Plan of sync config and DynamoDB"`
	Apply     *ApplyOption    `cmd:"" help:"Apply sync config and DynamoDB"`
	Version   struct{}        `cmd:"" help:"Show version"`
}

var (
	LevelDebug  slog.Level = slog.LevelDebug
	LevelInfo              = slog.LevelInfo
	LevelNotice            = slog.Level(slog.LevelInfo + 2)
	LevelWarn              = slog.LevelWarn
	LevelError             = slog.LevelError
)

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
	var minLevel slog.Level
	switch strings.ToLower(cli.LogLevel) {
	case "debug":
		minLevel = slog.LevelDebug
	case "info":
		minLevel = slog.LevelInfo
	case "notice":
		minLevel = slog.Level(slog.LevelInfo + 2)
	case "warn":
		minLevel = slog.LevelWarn
	case "error":
		minLevel = slog.LevelError
	default:
		return fmt.Errorf("unknown log level: %s", cli.LogLevel)
	}

	logMiddlwareOpts := slogutils.MiddlewareOptions{
		ModifierFuncs: map[slog.Level]slogutils.ModifierFunc{
			slog.LevelDebug: slogutils.Color(color.FgBlack),
			slog.LevelInfo:  nil,
			LevelNotice:     slogutils.Color(color.FgBlue),
			slog.LevelWarn:  slogutils.Color(color.FgYellow),
			slog.LevelError: slogutils.Color(color.FgRed, color.Bold),
		},
		RecordTransformerFuncs: []slogutils.RecordTransformerFunc{
			slogutils.ConvertLegacyLevel(
				map[string]slog.Level{
					"debug":  slog.LevelDebug,
					"info":   slog.LevelInfo,
					"notice": LevelNotice,
					"warn":   slog.LevelWarn,
					"error":  slog.LevelError,
				},
				true,
			),
		},
		Writer: os.Stderr,
		HandlerOptions: &slog.HandlerOptions{
			Level: minLevel,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if strings.Contains(a.Key, "email") && cli.MaskEmail {
					return slog.String("email", "********")
				}
				if a.Key == "quick_sight_user_arn" && cli.MaskEmail {
					arn, err := arn.Parse(a.Value.String())
					if err != nil {
						return slog.String("quick_sight_user_arn", "********")
					}
					parts := strings.Split(arn.Resource, "/")
					parts[len(parts)-1] = "********"
					arn.Resource = strings.Join(parts, "/")
					return slog.String("quick_sight_user_arn", arn.String())
				}
				if a.Key == "quick_sight_user_name" && cli.MaskEmail {
					parts := strings.Split(a.Value.String(), "/")
					parts[len(parts)-1] = "********"
					return slog.String("quick_sight_user_arn", strings.Join(parts, "/"))
				}
				if a.Key == slog.LevelKey {
					level := a.Value.Any().(slog.Level)
					switch {
					case level < LevelInfo:
						a.Value = slog.StringValue("DEBUG")
					case level < LevelNotice:
						a.Value = slog.StringValue("INFO")
					case level < LevelWarn:
						a.Value = slog.StringValue("NOTICE")
					case level < LevelError:
						a.Value = slog.StringValue("WARN")
					default:
						a.Value = slog.StringValue("ERROR")
					}
				}
				return a
			},
		},
	}
	slog.SetDefault(slog.New(slogutils.NewMiddleware(slog.NewJSONHandler, logMiddlwareOpts)).With(
		slog.String("app", "clipsight"),
		slog.String("version", Version),
	))
	cmd := strings.Fields(kctx.Command())[0]
	if cmd == "version" {
		fmt.Printf("clipsight %s\n", Version)
		return nil
	}
	app, err := New(ctx, cli.DDBTable, cli.MaskEmail)
	if err != nil {
		return err
	}
	return app.Dispatch(ctx, cmd, &cli)
}

func (app *ClipSight) Dispatch(ctx context.Context, command string, cli *CLI) error {
	switch command {
	case "register":
		return app.RunRegister(ctx, cli.Register)
	case "grant":
		return app.RunGrant(ctx, cli.Grant)
	case "serve":
		return app.RunServe(ctx, cli.Serve)
	case "revoke":
		return app.RunRevoke(ctx, cli.Revoke)
	case "plan":
		return app.RunPlan(ctx, cli.Plan)
	case "apply":
		return app.RunApply(ctx, cli.Apply)
	case "version":
		return nil
	}
	return fmt.Errorf("unknown command: %s", command)
}
