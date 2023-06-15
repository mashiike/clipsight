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
	var createdSummary, deletedSummary, changeSummary []string
	for _, change := range changes {
		if app.maskEmail {
			fmt.Fprintln(&details, change.String())
		} else {
			fmt.Fprintln(&details, change.UnmaskString())
		}
		if change.IsGroupChange() {
			if change.BeforeGroup == nil {
				created++
				createdSummary = append(createdSummary, fmt.Sprintf("group_id=%s(namespace:%s)", change.AfterGroup.ID, change.AfterGroup.Namespace))
				continue
			}
			if change.AfterGroup == nil {
				deleted++
				deletedSummary = append(deletedSummary, fmt.Sprintf("group_id=%s(namespace:%s)", change.BeforeGroup.ID, change.BeforeGroup.Namespace))
				continue
			}
			changeSummary = append(changeSummary, fmt.Sprintf("group_id=%s(namespace:%s)", change.AfterGroup.ID, change.AfterGroup.Namespace))
			continue
		}
		if change.IsUserChange() {
			if change.BeforeUser == nil {
				created++
				email := "********"
				if !app.maskEmail {
					email = change.AfterUser.Email.String()
				}
				createdSummary = append(createdSummary, fmt.Sprintf("user_id=%s(email:%s, namespace:%s)", change.AfterUser.ID, email, change.AfterUser.Namespace))
				continue
			}
			if change.AfterUser == nil {
				deleted++
				email := "********"
				if !app.maskEmail {
					email = change.BeforeUser.Email.String()
				}
				deletedSummary = append(deletedSummary, fmt.Sprintf("user_id=%s(email:%s, namespace:%s)", change.BeforeUser.ID, email, change.BeforeUser.Namespace))
				continue
			}
			email := "********"
			if !app.maskEmail {
				email = change.AfterUser.Email.String()
			}
			changeSummary = append(changeSummary, fmt.Sprintf("user_id=%s(email:%s, namespace:%s)", change.AfterUser.ID, email, change.AfterUser.Namespace))
			continue
		}
	}
	resourceChangeSummary := fmt.Sprintf("Plan: %d to create, %d to changes, %d to delete.\n\n", created, len(changes)-created-deleted, deleted)
	switch opt.Format {
	case "markdown":
		fmt.Println("## ClipSight Permission Changes")
		fmt.Println("")
		fmt.Printf("<pre><code>%s</code></pre>\n\n", resourceChangeSummary)
		if len(createdSummary) > 0 {
			fmt.Println("* Create")
			for _, user := range createdSummary {
				fmt.Printf("  * %s\n", user)
			}
			fmt.Println("")
		}
		if len(changeSummary) > 0 {
			fmt.Println("* Change")
			for _, user := range changeSummary {
				fmt.Printf("  * %s\n", user)
			}
			fmt.Println("")
		}
		if len(deletedSummary) > 0 {
			fmt.Println("* Delete")
			for _, user := range deletedSummary {
				fmt.Printf("  * %s\n", user)
			}
			fmt.Println("")
		}
		fmt.Println("")
		fmt.Printf("<details><summary>Details (Click me)</summary>\n\n```\n\n%s```\n\t%s\n</details>\n", details.String(), resourceChangeSummary)
	default:
		fmt.Println(details.String())
		fmt.Println("\t" + resourceChangeSummary)
	}
	return changes, nil
}
