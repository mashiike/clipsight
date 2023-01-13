package clipsight

import (
	"context"
	"fmt"
	"log"
	"time"
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

	log.Println("[debug] try get user", email)
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

	log.Println("[notice] grant dashboard", opt.DashboardID, "to", user.Email, "revision:", user.Revision)
	log.Println("[debug] user:", user)
	return nil
}
