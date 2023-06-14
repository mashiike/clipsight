package clipsight

import (
	"context"
	"fmt"
)

type UnassignGroupOption struct {
	GroupID string `help:"unassign target group id" required:""`
	Email   string `help:"user email address" required:""`
}

func (app *ClipSight) RunUnassignGroup(ctx context.Context, opt *UnassignGroupOption) error {
	email := Email(opt.Email)
	if err := email.Validate(); err != nil {
		return err
	}
	user, exists, err := app.GetUser(ctx, email)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if !exists {
		return fmt.Errorf("%s user not found", opt.Email)
	}
	group, exists, err := app.GetGroup(ctx, opt.GroupID)
	if err != nil {
		return fmt.Errorf("get group: %w", err)
	}
	if !exists {
		return fmt.Errorf("%s group not found", opt.GroupID)
	}
	if err := app.UnassignUserToGroup(ctx, user, group); err != nil {
		return fmt.Errorf("unassign user to group: %w", err)
	}
	return nil
}
