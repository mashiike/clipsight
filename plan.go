package clipsight

import (
	"context"
	"fmt"
)

type PlanOption struct {
	ConfigPath string `help:"config file path" required:"" default:"."`
	Silent     bool   `help:"silent mode"`
}

func (app *ClipSight) RunPlan(ctx context.Context, opt *PlanOption) error {
	cfg, err := LoadConfig(opt.ConfigPath)
	if err != nil {
		return err
	}
	changes, err := app.PlanSyncConfigToDynamoDB(ctx, cfg, opt.Silent)
	if err != nil {
		return err
	}
	var created, deleted int
	for _, change := range changes {
		if change.Before == nil {
			created++
		}
		if change.After == nil {
			deleted++
		}
		fmt.Println(change)
	}
	fmt.Printf("\tcreated: %d, changes: %d, deleted: %d\n\n", created, len(changes)-created-deleted, deleted)
	return nil
}
