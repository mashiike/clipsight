package clipsight

import (
	"context"
	"fmt"

	"golang.org/x/exp/slog"
)

type RevokeOption struct {
	Email       string `help:"user email address" required:""`
	DashboardID string `help:"revoke target dashboard id" required:""`
}

func (app *ClipSight) RunRevoke(ctx context.Context, opt *RevokeOption) error {
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
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if !exists {
		return fmt.Errorf("%s user not found", opt.Email)
	}
	if err := app.RevokeDashboardFromUser(ctx, user, opt.DashboardID); err != nil {
		return err
	}
	slog.Log(ctx, LevelNotice, "revoke dashboard", slog.String("dashboard_id", opt.DashboardID), slog.String("id", user.ID), slog.String("email", user.Email.String()), slog.Int64("revision", user.Revision))
	return nil
}
