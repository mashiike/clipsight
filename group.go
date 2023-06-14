package clipsight

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Songmu/flextime"
	"github.com/aws/aws-sdk-go-v2/service/quicksight/types"
	"github.com/guregu/dynamo"
	"golang.org/x/exp/slog"
)

type Group struct {
	schema
	ID                 string       `dynamodb:"ID" yaml:"id" json:"id"`
	Namespace          string       `dynamodb:"Namespace" yaml:"namespace" json:"namespace"`
	Dashboards         []*Dashboard `dynamodb:"Dashboards" yaml:"dashboards" json:"dashboards"`
	Region             string       `dynamodb:"Region" yaml:"region" json:"region"`
	CreatedAt          time.Time    `dynamodb:"CreatedAt,unixtime" yaml:"-" json:"-"`
	UpdatedAt          time.Time    `dynamodb:"UpdatedAt,unixtime" yaml:"-" json:"-"`
	QuickSightGroupARN string       `dynamodb:"QuickSightGroupARN" yaml:"-" json:"-"`
}

func (g *Group) Restrict() error {
	if g.ID == "" {
		return errors.New("id is required")
	}
	if g.Namespace == "" {
		g.Namespace = "default"
	}
	if g.Region == "" {
		g.Region = os.Getenv("AWS_REGION")
		if g.Region == "" {
			return errors.New("region is required")
		}
	}
	g.FillKey()
	for i, d := range g.Dashboards {
		if d.DashboardID == "" {
			return fmt.Errorf("dashboards[%d].dashboard_id is required", i)
		}
	}
	return nil
}

func NewGroup(groupID string) *Group {
	return (&Group{
		ID: groupID,
	}).FillKey()
}

func (g *Group) FillKey() *Group {
	g.HashKey = "GROUP"
	g.SortKey = "GROUP:" + g.ID
	return g
}

func (g *Group) IsNew() bool {
	return g.Revision == 0
}

func (g *Group) GrantDashboard(dashboard *types.Dashboard, expire time.Time) {
	for i, d := range g.Dashboards {
		if d.DashboardID == *dashboard.DashboardId {
			g.Dashboards[i].Expire = expire
			return
		}
	}
	g.Dashboards = append(g.Dashboards, &Dashboard{
		DashboardID: *dashboard.DashboardId,
		Expire:      expire,
	})
}

func (g *Group) RevokeDashboard(dashboardID string) bool {
	for i, d := range g.Dashboards {
		if d.DashboardID == dashboardID {
			g.Dashboards = append(g.Dashboards[:i], g.Dashboards[i+1:]...)
			return true
		}
	}
	return false
}

func (g *Group) EqualDashboardPermissions(other *Group) bool {
	if g == nil || other == nil {
		return g == nil && other == nil
	}
	if len(g.Dashboards) != len(other.Dashboards) {
		return false
	}
	// check dashboard element match by DashboardID
	grant, revoke := g.DiffPermissions(other)
	if len(grant) > 0 || len(revoke) > 0 {
		return false
	}
	return true
}

func (g *Group) DiffPermissions(other *Group) ([]*Dashboard, []*Dashboard) {
	a := make([]*Dashboard, 0, len(g.Dashboards))
	for _, d := range g.Dashboards {
		if !d.IsVisible() {
			continue
		}
		a = append(a, d)
	}
	b := make([]*Dashboard, 0, len(other.Dashboards))
	for _, d := range other.Dashboards {
		if !d.IsVisible() {
			continue
		}
		b = append(b, d)
	}
	added, changes, removed := ListDiff(a, b)
	return append(added, changes...), removed
}

func (app *ClipSight) GetGroup(ctx context.Context, groupID string) (*Group, bool, error) {
	group := NewGroup(groupID)
	if err := app.ddbTable().Get("HashKey", group.HashKey).Range("SortKey", dynamo.Equal, group.SortKey).Limit(1).OneWithContext(ctx, group); err != nil {
		if strings.Contains(err.Error(), "no item found") {
			return group, false, nil
		}
		return nil, false, err
	}
	return group, true, nil
}

func (app *ClipSight) GrantDashboardToGroup(ctx context.Context, group *Group, dashboardID string, expire time.Time) error {
	dashboard, exists, err := app.DescribeDashboard(ctx, dashboardID)
	if err != nil {
		return fmt.Errorf("describe quicksight user: %w", err)
	}
	if !exists {
		return fmt.Errorf("dashboard `%s` not found in %s account", dashboardID, app.awsAccountID)
	}
	slog.InfoCtx(ctx, "grant dashboard permission", slog.String("group_id", group.ID), slog.String("dashboard_name", *dashboard.Name), slog.String("dashboard_arn", *dashboard.Arn), slog.String("quick_sight_group_arn", group.QuickSightGroupARN))
	if err := app.GrantDashboardParmission(ctx, dashboardID, group.QuickSightGroupARN); err != nil {
		return fmt.Errorf("grant dashboard permission: %w", err)
	}

	group.GrantDashboard(dashboard, expire)
	slog.DebugCtx(ctx, "try save user", slog.String("user_id", group.ID))
	if err := app.SaveGroup(ctx, group); err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	return nil
}

func (app *ClipSight) RevokeDashboardFromGroup(ctx context.Context, group *Group, dashboardID string) error {
	if group.RevokeDashboard(dashboardID) {
		slog.DebugCtx(ctx, "try save group", slog.String("group_id", group.ID))
		if err := app.SaveGroup(ctx, group); err != nil {
			return fmt.Errorf("save group: %w", err)
		}
	}
	slog.DebugCtx(ctx, "try revoke dashboard permission", slog.String("group_id", group.ID), slog.String("dashboard_id", dashboardID), slog.String("quick_sight_group_arn", group.QuickSightGroupARN))
	if err := app.RevokeDashboardParmission(ctx, dashboardID, group.QuickSightGroupARN); err != nil {
		return fmt.Errorf("revoke dashboard permission: %w", err)
	}

	return nil
}

func (app *ClipSight) SaveGroup(ctx context.Context, group *Group) error {
	if err := group.Restrict(); err != nil {
		return err
	}
	rev := group.Revision
	group.Revision++
	if group.CreatedAt.IsZero() {
		group.CreatedAt = flextime.Now()
	}
	group.UpdatedAt = flextime.Now()
	putOp := app.ddbTable().Put(group)
	slog.DebugCtx(ctx, "update user item", slog.String("group_id", group.ID), slog.Int64("current_rivision", rev), slog.Int64("next_revision", group.Revision))
	if rev == 0 {
		putOp = putOp.If("attribute_not_exists(HashKey) AND attribute_not_exists(SortKey)")
	} else if rev > 0 {
		putOp = putOp.If("Revision = ?", rev)
	}
	return putOp.RunWithContext(ctx)
}
