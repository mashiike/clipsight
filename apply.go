package clipsight

import (
	"context"
	"fmt"
	"strings"

	"github.com/c-bata/go-prompt"
	"golang.org/x/exp/slog"
)

type ApplyOption struct {
	PlanOption
	AutoApprove bool `help:"auto approve"`
}

func (app *ClipSight) RunApply(ctx context.Context, opt *ApplyOption) error {
	changes, err := app.runPlan(ctx, &opt.PlanOption)
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		return nil
	}
	if !opt.AutoApprove {
		in := prompt.Input("Do you want to apply these changes? [y/N]", func(d prompt.Document) []prompt.Suggest {
			s := []prompt.Suggest{
				{Text: "yes", Description: "Answer yes"},
				{Text: "no", Description: "Answer no"},
			}
			return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
		})
		switch strings.ToLower(in) {
		case "yes", "y":
			// apply continue
		case "no", "n":
			return fmt.Errorf("canceled")
		default:
			return fmt.Errorf("invalid input")
		}
	}
	fmt.Print("Applying...", len(changes), " changes\n")
	for _, c := range changes {
		var email Email
		var id string
		if c.Before != nil {
			id = c.Before.ID
			email = c.Before.Email
		} else {
			id = c.After.ID
			email = c.After.Email
		}
		slog.DebugCtx(ctx, "change target dump", slog.String("id", id), slog.String("email", email.String()))
		if c.NeedRegister() {
			slog.DebugCtx(ctx, "need register", slog.String("id", id), slog.String("email", c.After.Email.String()))
			if err := app.RunRegister(ctx, &RegisterOption{
				ID:                     c.After.ID,
				Email:                  c.After.Email.String(),
				Namespace:              c.After.Namespace,
				IAMRoleARN:             c.After.IAMRoleARN,
				Region:                 c.After.Region,
				RegisterQuickSightUser: true,
				ExpireDate:             c.After.TTL,
			}); err != nil {
				return err
			}
		}
		if c.NeedPermissionModify() {
			slog.DebugCtx(ctx, "need permission modify", slog.String("id", id), slog.String("email", c.After.Email.String()))
			grant, revoke := c.Before.DiffPermissions(c.After)
			for _, g := range grant {
				slog.DebugCtx(ctx, "grant permission", slog.String("id", id), slog.String("email", c.After.Email.String()), slog.String("dashboard_id", g.DashboardID))
				if err := app.RunGrant(ctx, &GrantOption{
					Email:       c.After.Email.String(),
					DashboardID: g.DashboardID,
					ExpireDate:  g.Expire,
				}); err != nil {
					return err
				}
			}
			for _, r := range revoke {
				slog.DebugCtx(ctx, "revoke permission", slog.String("id", id), slog.String("email", c.Before.Email.String()), slog.String("dashboard_id", r.DashboardID))
				if err := app.RunRevoke(ctx, &RevokeOption{
					Email:       c.Before.Email.String(),
					DashboardID: r.DashboardID,
				}); err != nil {
					return err
				}
			}
		}
		if c.NeedDeregister() {
			slog.DebugCtx(ctx, "need deregister", slog.String("id", id), slog.String("email", c.Before.Email.String()))
			if err := app.RunDeregister(ctx, &DeregisterOption{
				Email: c.Before.Email.String(),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
