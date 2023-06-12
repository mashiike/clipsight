package clipsight

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/exp/slog"
)

type GrantOption struct {
	Email       string    `help:"user email address" required:""`
	DashboardID string    `help:"grant target dashboard id" required:""`
	ExpireDate  time.Time `help:"Expiration date for this user (RFC3399)"`
}

func (app *ClipSight) RunGrant(ctx context.Context, opt *GrantOption) error {
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
		return fmt.Errorf("%s user not found: please register", opt.Email)
	}
	if !user.IsActive() {
		return fmt.Errorf("%s user is not active", user.Email)
	}

	if err := app.GrantDashboardToUser(ctx, user, opt.DashboardID, opt.ExpireDate); err != nil {
		return err
	}

	slog.Log(ctx, LevelNotice, "grant dashboard", slog.String("dashboard_id", opt.DashboardID), slog.String("email", user.Email.String()), slog.Int64("revision", user.Revision))
	return nil
}
