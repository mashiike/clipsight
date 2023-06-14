package clipsight

import (
	"context"
	"fmt"

	"github.com/Songmu/flextime"
	"golang.org/x/exp/slog"
)

type DeleteGroupOption struct {
	GroupID             string `help:"group id to delete"`
	DisableOnly         bool   `name:"disable-only" help:"only disable group, not delete"`
	KeepQuickSightGroup bool   `name:"keep-quicksight-group" help:"if quicksight user exists, not delete this"`
	SetTTLOnly          bool   `name:"set-ttl-only" help:"only set ttl, not "`
}

func (app *ClipSight) RunDeleteGroup(ctx context.Context, opt *DeleteGroupOption) error {
	if err := app.prepareDynamoDB(ctx); err != nil {
		return err
	}
	slog.DebugCtx(ctx, "try get group", slog.String("group_id", opt.GroupID))
	group, exists, err := app.GetGroup(ctx, opt.GroupID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if !exists {
		return nil
	}
	group.Enabled = false
	if opt.DisableOnly {
		slog.DebugCtx(ctx, "try save group for disable", slog.String("group_id", opt.GroupID))
		if err := app.SaveGroup(ctx, group); err != nil {
			return fmt.Errorf("update group: %w", err)
		}
		slog.Log(ctx, LevelNotice, "disable group", slog.String("group_id", group.ID), slog.Int64("revision", group.Revision))
		return nil
	}

	if !opt.KeepQuickSightGroup {
		slog.DebugCtx(ctx, "try get quicksight group", slog.String("group_id", opt.GroupID))
		if exists {
			if err := app.DeleteQuickSightGroup(ctx, group); err != nil {
				return fmt.Errorf("delete group: %w", err)
			}
			slog.Log(ctx, LevelNotice, "QuickSight group found, and delete this user", slog.String("group_id", group.ID))
		}
	}
	group.TTL = flextime.Now()
	if opt.SetTTLOnly {
		slog.DebugCtx(ctx, "try set ttl group", slog.String("group_id", opt.GroupID))
		if err := app.SaveGroup(ctx, group); err != nil {
			return fmt.Errorf("save user: %w", err)
		}
	} else {
		slog.DebugCtx(ctx, "try delete group", slog.String("group_id", opt.GroupID))
		if err := app.DeleteGroup(ctx, group); err != nil {
			return fmt.Errorf("delete group: %w", err)
		}
	}
	slog.Log(ctx, LevelNotice, "delete group", slog.String("group_id", group.ID), slog.Int64("revision", group.Revision), slog.Time("ttl", group.TTL))
	return nil
}
