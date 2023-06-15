package clipsight

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/exp/slog"
)

// CreateGroupOption is Options for CLI Serve command
type CreateGroupOption struct {
	GroupID               string    `help:"group id"`
	Namespace             string    `help:"quicksight namespace" default:"default" required:""`
	Region                string    `help:"quicksight user region" env:"AWS_DEFAULT_REGION" required:""`
	CreateQuickSightGroup bool      `name:"create-quicksight-group" help:"if quicksight group not exists, create this"`
	ExpireDate            time.Time `help:"Expiration date for this group (RFC3399)"`
	Disabled              bool      `help:"disable user"`
}

func (app *ClipSight) RunCreateGroup(ctx context.Context, opt *CreateGroupOption) error {
	if err := app.prepareDynamoDB(ctx); err != nil {
		return err
	}
	slog.DebugCtx(ctx, "try get group", slog.String("group_id", opt.GroupID))
	group, exists, err := app.GetGroup(ctx, opt.GroupID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if !exists {
		slog.InfoCtx(ctx, "group not found, create new group", slog.String("id", group.ID))
		group = NewGroup(opt.GroupID)
	}
	group.Namespace = opt.Namespace
	group.Region = opt.Region
	group.Enabled = !opt.Disabled
	if !opt.ExpireDate.IsZero() {
		group.TTL = opt.ExpireDate
	} else {
		group.TTL = time.Time{}
	}

	slog.DebugCtx(ctx, "try get quicksight group")
	qsGroup, exists, err := app.DescribeQuickSightGroup(ctx, group)
	if err != nil {
		return fmt.Errorf("describe quicksight user: %w", err)
	}
	if !exists {
		if !opt.CreateQuickSightGroup {
			return fmt.Errorf("quicksight group `%s` in namespace `%s` not found", group.ID, group.Namespace)
		}
		qsGroup, err = app.CreateQuickSightGroup(ctx, group)
		if err != nil {
			return fmt.Errorf("register user: %w", err)
		}
		slog.Log(ctx, LevelNotice, "create quicksight group", slog.String("group_id", group.ID), slog.String("namespace", group.Namespace))
	}
	group.QuickSightGroupARN = *qsGroup.Arn
	slog.InfoCtx(ctx, "related quicksight group", slog.String("group_id", group.ID), slog.String("namespace", group.Namespace), slog.String("quick_sight_group_arn", *qsGroup.Arn))
	if err := app.SaveGroup(ctx, group); err != nil {
		return fmt.Errorf("save group: %w", err)
	}
	slog.Log(ctx, LevelNotice, "create", slog.String("group_id", group.ID), slog.Int64("revision", group.Revision))
	return nil
}
