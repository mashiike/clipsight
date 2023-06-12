package clipsight

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/c-bata/go-prompt"
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
		if c.Before != nil {
			email = c.Before.Email
		} else {
			email = c.After.Email
		}
		log.Printf("[debug] user: %s", email)
		if c.NeedRegister() {
			log.Printf("[debug] need register: %s", c.After.Email)
			if err := app.RunRegister(ctx, &RegisterOption{
				Email:                  c.After.Email.String(),
				Namespace:              c.After.Namespace,
				IAMRoleARN:             c.After.IAMRoleARN,
				Region:                 c.After.Region,
				RegisterQuickSightUser: true,
				Disabled:               !c.After.Enabled,
				ExpireDate:             c.After.TTL,
			}); err != nil {
				return err
			}
		}
		if c.NeedPermissionModify() {
			log.Println("[debug] need permission modify")
			grant, revoke := c.Before.DiffPermissions(c.After)
			for _, g := range grant {
				log.Printf("[debug] grant permission: %s to %s", g.DashboardID, c.After.Email)
				if err := app.RunGrant(ctx, &GrantOption{
					Email:       c.After.Email.String(),
					DashboardID: g.DashboardID,
					ExpireDate:  g.Expire,
				}); err != nil {
					return err
				}
			}
			for _, r := range revoke {
				log.Printf("[debug] revoke permission: %s from %s", r.DashboardID, c.Before.Email)
				if err := app.RunRevoke(ctx, &RevokeOption{
					Email:       c.Before.Email.String(),
					DashboardID: r.DashboardID,
				}); err != nil {
					return err
				}
			}
		}
		if c.NeedDeregister() {
			log.Println("[debug] need deregister")
			if err := app.RunDeregister(ctx, &DeregisterOption{
				Email: c.Before.Email.String(),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
