package clipsight

import (
	"context"
	"fmt"
	"strings"
)

type PlanOption struct {
	ConfigPath string `help:"config file path" required:"" default:"."`
	Silent     bool   `help:"silent mode"`
	Format     string `help:"output format" default:"text" enum:"text,markdown"`
}

func (app *ClipSight) RunPlan(ctx context.Context, opt *PlanOption) error {
	_, err := app.runPlan(ctx, opt)
	return err
}

func (app *ClipSight) runPlan(ctx context.Context, opt *PlanOption) ([]*ChangeInfo, error) {
	cfg, err := LoadConfig(opt.ConfigPath)
	if err != nil {
		return nil, err
	}
	changes, err := app.PlanSyncConfigToDynamoDB(ctx, cfg, opt.Silent)
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 {
		switch opt.Format {
		case "markdown":
			fmt.Println("## ClipSight Permission Changes")
			fmt.Println("")
			fmt.Println("<pre><code>No changes</code></pre>")
		default:
			fmt.Println("No changes")
		}
		return nil, nil
	}
	var details strings.Builder
	var created, deleted int
	var createdUsers, deletedUsers, changeUsers []string
	for _, change := range changes {
		if app.maskEmail {
			fmt.Fprintln(&details, change.String())
		} else {
			fmt.Fprintln(&details, change.UnmaskString())
		}
		if change.Before == nil {
			created++
			email := "********"
			if !app.maskEmail {
				email = change.After.Email.String()
			}
			createdUsers = append(createdUsers, fmt.Sprintf("%s(%s)", change.After.ID, email))
			continue
		}
		if change.After == nil {
			deleted++
			email := "********"
			if !app.maskEmail {
				email = change.Before.Email.String()
			}
			deletedUsers = append(deletedUsers, fmt.Sprintf("%s(%s)", change.Before.ID, email))
			continue
		}
		changeUsers = append(changeUsers, fmt.Sprintf("%s(%s)", change.After.ID, change.After.Email.String()))

	}
	resourceChangeSummary := fmt.Sprintf("Plan: %d to create, %d to changes, %d to delete.\n\n", created, len(changes)-created-deleted, deleted)
	switch opt.Format {
	case "markdown":
		fmt.Println("## ClipSight Permission Changes")
		fmt.Println("")
		fmt.Printf("<pre><code>%s</code></pre>\n", resourceChangeSummary)
		fmt.Printf("<details><summary>Details (Click me)</summary>\n\n```\n\n%s```\n\t%s\n</details>\n", details.String(), resourceChangeSummary)
	default:
		fmt.Println(details.String())
		fmt.Println("\t" + resourceChangeSummary)
	}
	return changes, nil
}
