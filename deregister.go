package clipsight

import (
	"context"
	"fmt"

	"github.com/Songmu/flextime"
	"golang.org/x/exp/slog"
)

type DeregisterOption struct {
	Email              string `help:"user email address" required:""`
	DisableOnly        bool   `name:"disable-only" help:"only disable user, not deregister"`
	KeepQuickSightUser bool   `name:"keep-quicksight-user" help:"if quicksight user exists, not deregister this"`
	SetTTLOnly         bool   `name:"set-ttl-only" help:"only set ttl, not deregister"`
}

func (app *ClipSight) RunDeregister(ctx context.Context, opt *DeregisterOption) error {
	email := Email(opt.Email)
	if err := email.Validate(); err != nil {
		return fmt.Errorf("validate email: %w", err)
	}
	if err := app.prepareDynamoDB(ctx); err != nil {
		return err
	}
	slog.DebugCtx(ctx, "try get user", slog.String("email", email.String()))
	user, exists, err := app.GetUser(ctx, email)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if !exists {
		return nil
	}
	user.Enabled = false
	if opt.DisableOnly {
		slog.DebugCtx(ctx, "try deregister user", slog.String("email", email.String()))
		if err := app.SaveUser(ctx, user); err != nil {
			return fmt.Errorf("update user: %w", err)
		}
		slog.Log(ctx, LevelNotice, "disable user", slog.String("id", user.ID), slog.String("email", email.String()), slog.Int64("revision", user.Revision))
		return nil
	}

	if !opt.KeepQuickSightUser {
		slog.DebugCtx(ctx, "try get quicksight user", slog.String("email", email.String()))
		if exists {
			if err := app.DeleteQuickSightUser(ctx, user); err != nil {
				return fmt.Errorf("deregister user: %w", err)
			}
			userName, err := user.QuickSightUserName()
			if err != nil {
				return fmt.Errorf("get quicksight user name: %w", err)
			}
			slog.Log(ctx, LevelNotice, "QuickSight user found, and deregister this user", slog.String("id", user.ID), slog.String("email", email.String()), slog.String("quick_sight_user_name", userName))
		}
	}
	user.TTL = flextime.Now()
	if opt.SetTTLOnly {
		slog.DebugCtx(ctx, "try set ttl user", slog.String("email", email.String()))
		if err := app.SaveUser(ctx, user); err != nil {
			return fmt.Errorf("save user: %w", err)
		}
	} else {
		slog.DebugCtx(ctx, "try delete user", slog.String("email", email.String()))
		if err := app.DeleteUser(ctx, user); err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
	}
	slog.Log(ctx, LevelNotice, "deregister user", slog.String("id", user.ID), slog.String("email", email.String()), slog.Int64("revision", user.Revision), slog.Time("ttl", user.TTL))
	return nil
}
