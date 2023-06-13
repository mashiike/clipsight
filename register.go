package clipsight

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/exp/slog"
)

// RegisterOption is Options for CLI Serve command
type RegisterOption struct {
	ID                     string    `help:"user id"`
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
	slog.DebugCtx(ctx, "try get user", slog.String("email", email.String()))
	user, exists, err := app.GetUser(ctx, email)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if !exists {
		slog.InfoCtx(ctx, "user not found, create new user", slog.String("id", user.ID), slog.String("email", email.String()))
		user = NewUser(email)
	}
	user.ID = opt.ID
	user.Namespace = opt.Namespace
	user.IAMRoleARN = opt.IAMRoleARN
	user.Region = opt.Region
	user.Enabled = !opt.Disabled
	if !opt.ExpireDate.IsZero() {
		user.TTL = opt.ExpireDate
	} else {
		user.TTL = time.Time{}
	}

	slog.DebugCtx(ctx, "try get quicksight user")
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
		slog.Log(ctx, LevelNotice, "register quicksight user", slog.String("id", user.ID), slog.String("namespace", user.Namespace), slog.String("email", user.Email.String()), slog.String("quick_sight_user_name", userName))
	}
	user.QuickSightUserARN = *qsUser.Arn
	slog.InfoCtx(ctx, "related quicksight user", slog.String("id", user.ID), slog.String("namespace", user.Namespace), slog.String("email", user.Email.String()), slog.String("quick_sight_user_name", *qsUser.UserName), slog.String("quick_sight_user_arn", *qsUser.Arn))
	slog.DebugCtx(ctx, "try get save user", slog.String("id", user.ID), slog.String("email", user.Email.String()))
	if err := app.SaveUser(ctx, user); err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	slog.Log(ctx, LevelNotice, "register", slog.String("id", user.ID), slog.String("email", user.Email.String()), slog.Int64("revision", user.Revision))
	return nil
}
