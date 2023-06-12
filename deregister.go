package clipsight

import (
	"context"
	"fmt"
	"log"

	"github.com/Songmu/flextime"
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

	log.Println("[debug] try get user", email)
	user, exists, err := app.GetUser(ctx, email)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if !exists {
		return nil
	}
	user.Enabled = false
	if !opt.DisableOnly {
		log.Println("[debug] try set disable user")
		if err := app.SaveUser(ctx, user); err != nil {
			return fmt.Errorf("update user: %w", err)
		}
		log.Println("[notice] disable user", user.Email, "revision:", user.Revision)
		return nil
	}

	if !opt.KeepQuickSightUser {
		log.Println("[debug] try get quicksight user")
		if exists {
			if err := app.DeleteQuickSightUser(ctx, user); err != nil {
				return fmt.Errorf("deregister user: %w", err)
			}
			userName, err := user.QuickSightUserName()
			if err != nil {
				return fmt.Errorf("get quicksight user name: %w", err)
			}

			log.Printf("[notice] quicksight user `%s` in namespace `%s` found, and deregister this user as reader", userName, user.Namespace)
		}
	}
	user.TTL = flextime.Now()
	if opt.SetTTLOnly {
		log.Println("[debug] try set ttl user")
		if err := app.SaveUser(ctx, user); err != nil {
			return fmt.Errorf("save user: %w", err)
		}
	} else {
		log.Println("[debug] try delete user")
		if err := app.DeleteUser(ctx, user); err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
	}
	log.Println("[notice] deregister", user.Email, "revision:", user.Revision, "TTL:", user.TTL)
	log.Println("[debug] user:", user)
	return nil
}
