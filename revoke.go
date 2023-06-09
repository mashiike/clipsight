package clipsight

import (
	"context"
	"fmt"
	"log"
)

type RevokeOption struct {
	Email       string `help:"user email address" required:""`
	DashboardID string `help:"revoke target dashboard id" required:""`
}

func (app *ClipSight) RunRevoke(ctx context.Context, opt *RevokeOption) error {
	if !app.isDDBMode() {
		return fmt.Errorf("revoke command is only available in ddb mode")
	}
	email := Email(opt.Email)
	if err := email.Validate(); err != nil {
		return fmt.Errorf("validate email: %w", err)
	}

	log.Println("[debug] try get user", email)
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
	log.Println("[notice] revoke dashboard", opt.DashboardID, "from", user.Email, "revision:", user.Revision)
	log.Println("[debug] user:", user)
	return nil
}
