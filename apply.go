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
		if c.IsGroupChange() {
			id := c.GroupID()
			slog.DebugCtx(ctx, "change target dump", slog.String("group_id", id))
			if c.NeedCreateGroup() {
				slog.DebugCtx(ctx, "create group", slog.String("group_id", id))
				if err := app.RunCreateGroup(ctx, &CreateGroupOption{
					GroupID:               id,
					Namespace:             c.AfterGroup.Namespace,
					Region:                c.AfterGroup.Region,
					CreateQuickSightGroup: true,
					ExpireDate:            c.AfterGroup.TTL,
					Disabled:              !c.AfterGroup.Enabled,
				}); err != nil {
					return err
				}
			}
			if c.NeedPermissionModify() {
				grant, revoke := c.BeforeGroup.DiffPermissions(c.AfterGroup)
				for _, g := range grant {
					slog.DebugCtx(ctx, "grant permission", slog.String("group_id", id), slog.String("dashboard_id", g.DashboardID))
					if err := app.RunGrant(ctx, &GrantOption{
						GroupID:     c.AfterGroup.ID,
						DashboardID: g.DashboardID,
						ExpireDate:  g.Expire,
					}); err != nil {
						return err
					}
				}
				for _, r := range revoke {
					slog.DebugCtx(ctx, "revoke permission", slog.String("group_id", id), slog.String("dashboard_id", r.DashboardID))
					if err := app.RunRevoke(ctx, &RevokeOption{
						GroupID:     c.AfterGroup.ID,
						DashboardID: r.DashboardID,
					}); err != nil {
						return err
					}
				}
			}
			if c.NeedDeleteGroup() {
				slog.DebugCtx(ctx, "delete group", slog.String("group_id", id))
				if err := app.RunDeleteGroup(ctx, &DeleteGroupOption{
					GroupID: id,
				}); err != nil {
					return err
				}
			}
		}
		if c.IsUserChange() {
			email := c.Email()
			id := c.UserID()
			slog.DebugCtx(ctx, "change target dump", slog.String("id", id), slog.String("email", email.String()))
			if c.NeedRegister() {
				slog.DebugCtx(ctx, "need register", slog.String("id", id), slog.String("email", c.AfterUser.Email.String()))
				if err := app.RunRegister(ctx, &RegisterOption{
					ID:                     c.AfterUser.ID,
					Email:                  c.AfterUser.Email.String(),
					Namespace:              c.AfterUser.Namespace,
					IAMRoleARN:             c.AfterUser.IAMRoleARN,
					Region:                 c.AfterUser.Region,
					ProvisioningAs:         c.AfterUser.ProvisioningAs,
					CanConsole:             c.AfterUser.CanConsole,
					RegisterQuickSightUser: true,
					ExpireDate:             c.AfterUser.TTL,
				}); err != nil {
					return err
				}
			}
			if c.NeedPermissionModify() {
				slog.DebugCtx(ctx, "need permission modify", slog.String("id", id), slog.String("email", c.AfterUser.Email.String()))
				grant, revoke := c.BeforeUser.DiffPermissions(c.AfterUser)
				for _, g := range grant {
					slog.DebugCtx(ctx, "grant permission", slog.String("id", id), slog.String("email", c.AfterUser.Email.String()), slog.String("dashboard_id", g.DashboardID))
					if err := app.RunGrant(ctx, &GrantOption{
						Email:       c.AfterUser.Email.String(),
						DashboardID: g.DashboardID,
						ExpireDate:  g.Expire,
					}); err != nil {
						return err
					}
				}
				for _, r := range revoke {
					slog.DebugCtx(ctx, "revoke permission", slog.String("id", id), slog.String("email", c.BeforeUser.Email.String()), slog.String("dashboard_id", r.DashboardID))
					if err := app.RunRevoke(ctx, &RevokeOption{
						Email:       c.BeforeUser.Email.String(),
						DashboardID: r.DashboardID,
					}); err != nil {
						return err
					}
				}
			}
			if c.NeedGroupModify() {
				slog.DebugCtx(ctx, "need group modify", slog.String("id", id), slog.String("email", c.AfterUser.Email.String()))
				assign, unassign := c.BeforeUser.DiffGroups(c.AfterUser)
				for _, a := range assign {
					slog.DebugCtx(ctx, "assign group", slog.String("id", id), slog.String("email", c.AfterUser.Email.String()), slog.String("group_id", string(a)))
					if err := app.RunAssignGroup(ctx, &AssignGroupOption{
						Email:   c.AfterUser.Email.String(),
						GroupID: string(a),
					}); err != nil {
						return err
					}
				}
				for _, u := range unassign {
					slog.DebugCtx(ctx, "unassign group", slog.String("id", id), slog.String("email", c.BeforeUser.Email.String()), slog.String("group_id", string(u)))
					if err := app.RunUnassignGroup(ctx, &UnassignGroupOption{
						Email:   c.BeforeUser.Email.String(),
						GroupID: string(u),
					}); err != nil {
						return err
					}
				}
			}
			if c.NeedDeregister() {
				slog.DebugCtx(ctx, "need deregister", slog.String("id", id), slog.String("email", c.BeforeUser.Email.String()))
				if err := app.RunDeregister(ctx, &DeregisterOption{
					Email: c.BeforeUser.Email.String(),
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
