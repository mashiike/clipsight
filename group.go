package clipsight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Songmu/flextime"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	"github.com/aws/aws-sdk-go-v2/service/quicksight/types"
	"github.com/guregu/dynamo"
	"github.com/pmezard/go-difflib/difflib"
	"golang.org/x/exp/slog"
)

type Group struct {
	schema
	ID                 string       `dynamodb:"ID" yaml:"id" json:"id"`
	Namespace          string       `dynamodb:"Namespace" yaml:"namespace" json:"namespace"`
	Dashboards         []*Dashboard `dynamodb:"Dashboards" yaml:"dashboards" json:"dashboards"`
	Region             string       `dynamodb:"Region" yaml:"region" json:"region"`
	Enabled            bool         `dynamodb:"Enabled" yaml:"enabled" json:"enabled"`
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

func (g *Group) IsActive() bool {
	if g.schema.IsExpire() {
		return false
	}
	return g.Enabled
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

func (g *Group) Equals(other *Group) bool {
	if g == nil || other == nil {
		return g == nil && other == nil
	}
	if g.ID != other.ID {
		return false
	}
	if g.Namespace != other.Namespace {
		return false
	}
	if g.Region != other.Region {
		return false
	}
	if g.TTL != other.TTL {
		return false
	}
	return g.Enabled == other.Enabled
}

func (g *Group) EqualIdentifiers(other *Group) bool {
	if g == nil || other == nil {
		return g == nil && other == nil
	}
	return g.ID == other.ID && g.Namespace == other.Namespace
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

func (g *Group) HasChanges(other *Group) bool {
	return !g.Equals(other) || !g.EqualDashboardPermissions(other)
}

func (g *Group) Diff(group *Group) (string, error) {
	current, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return "", err
	}
	currentStr := string(current)
	other, err := json.MarshalIndent(group, "", "  ")
	if err != nil {
		return "", err
	}
	otherStr := string(other)
	currentLines := difflib.SplitLines(currentStr)
	otherLines := difflib.SplitLines(otherStr)
	diff := difflib.UnifiedDiff{
		A:       currentLines,
		B:       otherLines,
		Context: len(currentLines) + len(otherLines),
	}

	text, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return "", err
	}
	return text, nil
}

func (g *Group) DiffPermissions(other *Group) ([]*Dashboard, []*Dashboard) {
	var a []*Dashboard
	if g != nil {
		a = make([]*Dashboard, 0, len(g.Dashboards))
		for _, d := range g.Dashboards {
			if !d.IsVisible() {
				continue
			}
			a = append(a, d)
		}
	}
	var b []*Dashboard
	if other != nil {
		b = make([]*Dashboard, 0, len(other.Dashboards))
		for _, d := range other.Dashboards {
			if !d.IsVisible() {
				continue
			}
			b = append(b, d)
		}
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

func (app *ClipSight) DeleteGroup(ctx context.Context, group *Group) error {
	return app.ddbTable().Delete("HashKey", group.HashKey).Range("SortKey", group.SortKey).RunWithContext(ctx)
}

func (app *ClipSight) CreateQuickSightGroup(ctx context.Context, group *Group) (*types.Group, error) {
	slog.DebugCtx(ctx, "try CreateQuicksightGroup", slog.String("group_id", group.ID))
	output, err := app.qs.CreateGroup(ctx, &quicksight.CreateGroupInput{
		AwsAccountId: aws.String(app.awsAccountID),
		Namespace:    aws.String(group.Namespace),
		GroupName:    aws.String(group.ID),
		Description:  aws.String("Managed by ClipSight. "),
	})
	if err != nil {
		return nil, err
	}
	if output.Status != http.StatusCreated {
		return nil, fmt.Errorf("HTTP Status %d", output.Status)
	}
	return output.Group, nil
}

func (app *ClipSight) DescribeQuickSightGroup(ctx context.Context, group *Group) (*types.Group, bool, error) {
	slog.DebugCtx(ctx, "try DescribeQuicksightGroup", slog.String("group_id", group.ID))
	output, err := app.qs.DescribeGroup(ctx, &quicksight.DescribeGroupInput{
		AwsAccountId: aws.String(app.awsAccountID),
		Namespace:    aws.String(group.Namespace),
		GroupName:    aws.String(group.ID),
	})
	if err != nil {
		var rnf *types.ResourceNotFoundException
		if !errors.As(err, &rnf) {
			return nil, false, err
		}
		return nil, false, nil
	}
	if output.Status != http.StatusOK {
		return nil, false, fmt.Errorf("HTTP Status %d", output.Status)
	}
	return output.Group, true, nil
}

func (app *ClipSight) DeleteQuickSightGroup(ctx context.Context, group *Group) error {
	_, exists, err := app.DescribeQuickSightGroup(ctx, group)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	slog.DebugCtx(ctx, "try DeleteQuicksightGroup", slog.String("group_id", group.ID))
	output, err := app.qs.DeleteGroup(ctx, &quicksight.DeleteGroupInput{
		AwsAccountId: aws.String(app.awsAccountID),
		Namespace:    aws.String(group.Namespace),
		GroupName:    aws.String(group.ID),
	})
	if err != nil {
		return err
	}
	if output.Status != http.StatusOK {
		return fmt.Errorf("HTTP Status %d", output.Status)
	}
	return nil
}

func (app *ClipSight) AssignUserToGroup(ctx context.Context, user *User, group *Group) error {
	slog.DebugCtx(ctx, "try AssignUserToGroup", slog.String("user_id", user.ID), slog.String("group_id", group.ID))
	if user.Namespace != group.Namespace {
		return fmt.Errorf("user and group namespace mismatch")
	}
	if err := app.CreateGroupMemberShip(ctx, user, group); err != nil {
		return err
	}
	if ListContains(user.Groups, UserGroupMembership(group.ID)) {
		return nil
	}
	user.Groups = append(user.Groups, UserGroupMembership(group.ID))
	return app.SaveUser(ctx, user)
}

func (app *ClipSight) CreateGroupMemberShip(ctx context.Context, user *User, group *Group) error {
	userName, err := user.QuickSightUserName()
	if err != nil {
		return err
	}
	output, err := app.qs.CreateGroupMembership(ctx, &quicksight.CreateGroupMembershipInput{
		AwsAccountId: aws.String(app.awsAccountID),
		Namespace:    aws.String(group.Namespace),
		GroupName:    aws.String(group.ID),
		MemberName:   aws.String(userName),
	})
	if err != nil {
		return err
	}
	if output.Status != http.StatusOK {
		return fmt.Errorf("HTTP Status %d", output.Status)
	}
	return nil
}

func (app *ClipSight) UnassignUserToGroup(ctx context.Context, user *User, group *Group) error {
	slog.DebugCtx(ctx, "try UnassignUserToGroup", slog.String("user_id", user.ID), slog.String("group_id", group.ID))
	if err := app.DeleteGroupMemberShip(ctx, user, group); err != nil {
		return fmt.Errorf("failed to delete group membership: %w", err)
	}
	var found bool
	for i, g := range user.Groups {
		if string(g) == group.ID {
			user.Groups = append(user.Groups[:i], user.Groups[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	return app.SaveUser(ctx, user)
}

func (app *ClipSight) DescribeGroupMemberShip(ctx context.Context, user *User, group *Group) (bool, error) {
	userName, err := user.QuickSightUserName()
	if err != nil {
		return false, err
	}
	_, err = app.qs.DescribeGroupMembership(ctx, &quicksight.DescribeGroupMembershipInput{
		AwsAccountId: aws.String(app.awsAccountID),
		Namespace:    aws.String(group.Namespace),
		GroupName:    aws.String(group.ID),
		MemberName:   aws.String(userName),
	})
	if err != nil {
		var rnf *types.ResourceNotFoundException
		if !errors.As(err, &rnf) {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

func (app *ClipSight) DeleteGroupMemberShip(ctx context.Context, user *User, group *Group) error {
	exits, err := app.DescribeGroupMemberShip(ctx, user, group)
	if err != nil {
		return err
	}
	if !exits {
		return nil
	}
	userName, err := user.QuickSightUserName()
	if err != nil {
		return err
	}
	output, err := app.qs.DeleteGroupMembership(ctx, &quicksight.DeleteGroupMembershipInput{
		AwsAccountId: aws.String(app.awsAccountID),
		Namespace:    aws.String(group.Namespace),
		GroupName:    aws.String(group.ID),
		MemberName:   aws.String(userName),
	})
	if err != nil {
		return err
	}
	if output.Status != http.StatusOK {
		return fmt.Errorf("HTTP Status %d", output.Status)
	}
	return nil
}

func (app *ClipSight) ListGroups(ctx context.Context) (<-chan *Group, func()) {
	ch := make(chan *Group, 100)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer func() {
			slog.DebugCtx(ctx, "list groups done")
			wg.Done()
		}()
		slog.DebugCtx(ctx, "list groups start")
		iter := app.ddbTable().Scan().Filter("'HashKey' = ?", "GROUP").Iter()
		for {
			var group Group
			isContinue := iter.NextWithContext(ctx, &group)
			if !isContinue {
				break
			}
			ch <- &group
		}
		if err := iter.Err(); err != nil {
			slog.ErrorCtx(ctx, "list groups error", "detail", err)
		}
		close(ch)
	}()
	return ch, wg.Wait
}
