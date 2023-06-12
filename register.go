package clipsight

import (
	"context"
	"fmt"
	"log"
	"time"
)

// RegisterOption is Options for CLI Serve command
type RegisterOption struct {
	Email                  string    `help:"user email address" required:""`
	Namespace              string    `help:"quicksight namespace" default:"default" required:""`
	IAMRoleARN             string    `help:"IAM Role arn for quicksight user" required:""`
	Region                 string    `help:"quicksight user region" env:"AWS_DEFAULT_REGION" required:""`
	RegisterQuickSightUser bool      `name:"register-quicksight-user" help:"if quicksight user not exists, register this"`
	ExpireDate             time.Time `help:"Expiration date for this user (RFC3399)"`
	Disabled               bool      `help:"disable user"`
}

func (app *ClipSight) RunRegister(ctx context.Context, opt *RegisterOption) error {
	if _, err := ParseIAMRoleARN(opt.IAMRoleARN); err != nil {
		return fmt.Errorf("%s: %w", opt.IAMRoleARN, err)
	}
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
		log.Printf("[info] create new user for %s", email)
		user = NewUser(email)
	}
	user.Namespace = opt.Namespace
	user.IAMRoleARN = opt.IAMRoleARN
	user.Region = opt.Region
	user.Enabled = !opt.Disabled
	if !opt.ExpireDate.IsZero() {
		user.TTL = opt.ExpireDate
	} else {
		user.TTL = time.Time{}
	}

	log.Println("[debug] try get quicksight user")
	qsUser, exists, err := app.DescribeQuickSightUser(ctx, user)
	if err != nil {
		return fmt.Errorf("describe quicksight user: %w", err)
	}
	if !exists {
		userName, _ := user.QuickSightUserName()
		if !opt.RegisterQuickSightUser {
			return fmt.Errorf("quicksight user `%s` in namespace `%s` not found", userName, user.Namespace)
		}
		qsUser, err = app.RegisterQuickSightUser(ctx, user)
		if err != nil {
			return fmt.Errorf("register user: %w", err)
		}
		log.Printf("[notice] quicksight user `%s` in namespace `%s` not found, and register this user as reader", userName, user.Namespace)
	}
	user.QuickSightUserARN = *qsUser.Arn
	log.Printf("[info] related quicksight user `%s`", *qsUser.Arn)
	log.Println("[debug] try save user", email)
	if err := app.SaveUser(ctx, user); err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	log.Println("[notice] register", user.Email, "revision:", user.Revision)
	log.Println("[debug] user:", user)
	return nil
}
