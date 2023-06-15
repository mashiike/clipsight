package clipsight

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	"github.com/aws/aws-sdk-go-v2/service/quicksight/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/guregu/dynamo"
	"golang.org/x/exp/slog"
)

var Version string = "current"

// Clipsight is Application instance for resource lifecycle
type ClipSight struct {
	ddbTableName string
	awsAccountID string
	maskEmail    bool
	qs           *quicksight.Client
	sts          *sts.Client
	ddb          *dynamo.DB
}

// New returns initialized application instance
func New(ctx context.Context, ddbTableName string, maskEmail bool) (*ClipSight, error) {
	awsCfgV2, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	stsClient := sts.NewFromConfig(awsCfgV2)
	getCallerIdentityOutput, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}
	app := &ClipSight{
		ddbTableName: ddbTableName,
		awsAccountID: *getCallerIdentityOutput.Account,
		qs:           quicksight.NewFromConfig(awsCfgV2),
		sts:          stsClient,
		maskEmail:    maskEmail,
		ddb:          dynamo.New(sess),
	}
	return app, nil
}

// Management table for github.com/mashiike/clipsight
type schema struct {
	HashKey string `dynamo:"HashKey,hash" ymal:"-" json:"-"`
	SortKey string `dynamo:"SortKey,range" ymal:"-" json:"-"`

	Revision int64     `dynamo:"Revision" yaml:"-" json:"-"`
	TTL      time.Time `dynamo:"TTL,unixtime,omitempty" yaml:"expire,omitempty" json:"expire,omitempty"`
}

func (s *schema) IsExpire() bool {
	if s.TTL.IsZero() {
		return false
	}
	return time.Now().UnixNano() >= s.TTL.UnixNano()
}

func (app *ClipSight) ddbTable() dynamo.Table {
	return app.ddb.Table(app.ddbTableName)
}

func (app *ClipSight) prepareDynamoDB(ctx context.Context) error {
	slog.DebugCtx(ctx, "try prepare DynamoDB")
	table := app.ddbTable()
	if _, err := table.Describe().RunWithContext(ctx); err != nil {
		var rnf *dynamodb.ResourceNotFoundException
		if !errors.As(err, &rnf) {
			return fmt.Errorf("describe table: %w", err)
		}
		if err := app.ddb.CreateTable(app.ddbTableName, &schema{}).OnDemand(true).RunWithContext(ctx); err != nil {
			return fmt.Errorf("create table: %w", err)
		}
		if err := table.WaitWithContext(ctx, dynamo.ActiveStatus); err != nil {
			return fmt.Errorf("wait table: %w", err)
		}
	}
	ttlDesc, err := table.DescribeTTL().RunWithContext(ctx)
	if err != nil {
		return fmt.Errorf("describe ttl: %w", err)
	}
	if ttlDesc.Attribute == "TTL" && (ttlDesc.Status == dynamo.TTLEnabled || ttlDesc.Status == dynamo.TTLEnabling) {
		return nil
	}
	if err := table.UpdateTTL("TTL", true).RunWithContext(ctx); err != nil {
		return fmt.Errorf("update ttl: %w", err)
	}
	return nil
}

func (app *ClipSight) DescribeDashboard(ctx context.Context, dashboardID string) (*types.Dashboard, bool, error) {
	slog.DebugCtx(ctx, "try DescribeDashboard(%s, %s)", slog.String("aws_account_id", app.awsAccountID), slog.String("dashboard_id", dashboardID))
	output, err := app.qs.DescribeDashboard(ctx, &quicksight.DescribeDashboardInput{
		AwsAccountId: aws.String(app.awsAccountID),
		DashboardId:  aws.String(dashboardID),
	})
	if err != nil {
		var rnf *types.ResourceNotFoundException
		if !errors.As(err, &rnf) {
			return nil, false, err
		}
		return &types.Dashboard{
			DashboardId: aws.String(dashboardID),
		}, false, nil
	}
	if output.Status != http.StatusOK {
		return nil, false, fmt.Errorf("HTTP Status %d", output.Status)
	}
	return output.Dashboard, true, nil
}

func (app *ClipSight) DescribeDashboardParmissions(ctx context.Context, dashboardID string) ([]types.ResourcePermission, error) {
	slog.DebugCtx(ctx, "try DescribeDashboardParmissions(%s, %s)", slog.String("aws_account_id", app.awsAccountID), slog.String("dashboard_id", dashboardID))
	output, err := app.qs.DescribeDashboardPermissions(ctx, &quicksight.DescribeDashboardPermissionsInput{
		AwsAccountId: aws.String(app.awsAccountID),
		DashboardId:  aws.String(dashboardID),
	})
	if err != nil {
		return nil, err
	}
	if output.Status != http.StatusOK {
		return nil, fmt.Errorf("HTTP Status %d", output.Status)
	}
	return output.Permissions, nil
}

func (app *ClipSight) GrantDashboardParmission(ctx context.Context, dashboardID string, principalARN string) error {
	permissions, err := app.DescribeDashboardParmissions(ctx, dashboardID)
	if err != nil {
		return fmt.Errorf("permission check: %w", err)
	}

	for _, permission := range permissions {
		if *permission.Principal == principalARN {
			return nil
		}
	}
	slog.DebugCtx(ctx, "try GrantDashboardParmission(%s, %s, %s)", slog.String("aws_account_id", app.awsAccountID), slog.String("dashboard_id", dashboardID), slog.String("principal_arn", principalARN))
	output, err := app.qs.UpdateDashboardPermissions(ctx, &quicksight.UpdateDashboardPermissionsInput{
		AwsAccountId: aws.String(app.awsAccountID),
		DashboardId:  aws.String(dashboardID),
		GrantPermissions: []types.ResourcePermission{
			{
				Principal: aws.String(principalARN),
				Actions: []string{
					"quicksight:DescribeDashboard",
					"quicksight:ListDashboardVersions",
					"quicksight:QueryDashboard",
				},
			},
		},
	})
	if err != nil {
		return err
	}
	if output.Status != http.StatusOK {
		return fmt.Errorf("HTTP Status %d", output.Status)
	}
	return nil
}

func (app *ClipSight) RevokeDashboardParmission(ctx context.Context, dashboardID string, principalARN string) error {
	permissions, err := app.DescribeDashboardParmissions(ctx, dashboardID)
	if err != nil {
		return fmt.Errorf("permission check: %w", err)
	}

	revokePermissions := make([]types.ResourcePermission, 0)
	for _, permission := range permissions {
		if *permission.Principal == principalARN {
			revokePermissions = append(revokePermissions, permission)
		}
	}
	if len(revokePermissions) == 0 {
		return nil
	}
	slog.DebugCtx(ctx, "try RevokeDashboardParmission(%s, %s, %s)", slog.String("aws_account_id", app.awsAccountID), slog.String("dashboard_id", dashboardID), slog.String("principal_arn", principalARN))
	output, err := app.qs.UpdateDashboardPermissions(ctx, &quicksight.UpdateDashboardPermissionsInput{
		AwsAccountId:      aws.String(app.awsAccountID),
		DashboardId:       aws.String(dashboardID),
		RevokePermissions: revokePermissions,
	})
	if err != nil {
		return err
	}
	if output.Status != http.StatusOK {
		return fmt.Errorf("HTTP Status %d", output.Status)
	}
	return nil
}

type ChangeInfo struct {
	BeforeGroup *Group
	AfterGroup  *Group
	BeforeUser  *User
	AfterUser   *User
}

func (c *ChangeInfo) String() string {
	return c.diffString(true)
}

func (c *ChangeInfo) UnmaskString() string {
	return c.diffString(false)
}

func (c *ChangeInfo) GroupID() string {
	if !c.IsGroupChange() {
		return ""
	}
	if c.BeforeGroup != nil {
		return c.BeforeGroup.ID
	}
	return c.AfterGroup.ID
}

func (c *ChangeInfo) UserID() string {
	if !c.IsUserChange() {
		return ""
	}
	if c.BeforeUser != nil {
		return c.BeforeUser.ID
	}
	return c.AfterUser.ID
}

func (c *ChangeInfo) Email() Email {
	if !c.IsUserChange() {
		return ""
	}
	if c.BeforeUser != nil {
		return c.BeforeUser.Email
	}
	return c.AfterUser.Email
}

func (c *ChangeInfo) diffString(mask bool) string {
	if c.IsGroupChange() {
		return c.diffStringForGroup(mask)
	}
	if c.IsUserChange() {
		return c.diffStringForUser(mask)
	}
	return ""
}

func (c *ChangeInfo) diffStringForGroup(_ bool) string {
	var builder strings.Builder
	builder.WriteString("QuickSightGroup: ")
	var namespace string
	var id string
	if c.BeforeGroup != nil {
		id = c.BeforeGroup.ID
		namespace = c.BeforeGroup.Namespace
	} else {
		id = c.AfterGroup.ID
		namespace = c.AfterGroup.Namespace
	}
	builder.WriteString(fmt.Sprintf("%s/%s", namespace, id))
	builder.WriteString("\n")
	diffStr, err := c.BeforeGroup.Diff(c.AfterGroup)
	if err != nil {
		fmt.Fprintf(&builder, "diff print error: %s\n", err)
	} else {
		builder.WriteString(diffStr)
	}
	builder.WriteString("\n")
	return builder.String()
}

func (c *ChangeInfo) diffStringForUser(mask bool) string {
	var builder strings.Builder
	builder.WriteString("QuickSightUser: ")
	var namespace string
	var userName string
	var email string
	if c.BeforeUser != nil {
		namespace = c.BeforeUser.Namespace
		userName, _ = c.BeforeUser.QuickSightUserName()
		email = c.BeforeUser.Email.String()
	}
	if userName == "" && c.AfterUser != nil {
		namespace = c.AfterUser.Namespace
		userName, _ = c.AfterUser.QuickSightUserName()
		email = c.AfterUser.Email.String()
	}
	if mask {
		userName = strings.ReplaceAll(userName, email, "******")
	}
	builder.WriteString(fmt.Sprintf("%s/%s", namespace, userName))
	builder.WriteString("\n")
	diffStr, err := c.BeforeUser.Diff(c.AfterUser, mask)
	if err != nil {
		fmt.Fprintf(&builder, "diff print error: %s\n", err)
	} else {
		builder.WriteString(diffStr)
	}
	builder.WriteString("\n")
	return builder.String()
}

func (c *ChangeInfo) IsUserChange() bool {
	return c.BeforeUser != nil || c.AfterUser != nil
}

func (c *ChangeInfo) IsGroupChange() bool {
	return c.BeforeGroup != nil || c.AfterGroup != nil
}

func (c *ChangeInfo) NeedRegister() bool {
	if !c.IsUserChange() {
		return false
	}
	if c.AfterUser == nil {
		return false
	}
	return !c.BeforeUser.Equals(c.AfterUser) && c.AfterUser.Enabled
}

func (c *ChangeInfo) NeedCreateGroup() bool {
	if !c.IsGroupChange() {
		return false
	}
	if c.AfterGroup == nil {
		return false
	}
	return !c.BeforeGroup.Equals(c.AfterGroup) && c.AfterGroup.Enabled
}

func (c *ChangeInfo) NeedGroupModify() bool {
	if !c.IsUserChange() {
		return false
	}
	if c.AfterUser == nil {
		return false
	}
	return !c.BeforeUser.EqualGroups(c.AfterUser)
}

func (c *ChangeInfo) NeedPermissionModify() bool {
	if c.AfterUser == nil && c.AfterGroup == nil {
		return false
	}
	return !c.BeforeUser.EqualDashboardPermissions(c.AfterUser) || !c.BeforeGroup.EqualDashboardPermissions(c.AfterGroup)
}

func (c *ChangeInfo) NeedDeregister() bool {
	if !c.IsUserChange() {
		return false
	}
	return c.AfterUser == nil
}

func (c *ChangeInfo) NeedDeleteGroup() bool {
	if !c.IsGroupChange() {
		return false
	}
	return c.AfterGroup == nil
}

func (app *ClipSight) PlanSyncConfigToDynamoDB(ctx context.Context, cfg *Config, silent bool) ([]*ChangeInfo, error) {
	slog.DebugCtx(ctx, "start PlanSyncConfigToDynamoDB")
	cg, err := app.planSyncConfigToDynamoDBForGroup(ctx, cfg, silent)
	if err != nil {
		return nil, err
	}
	cu, err := app.planSyncConfigToDynamoDBForUser(ctx, cfg, silent)
	if err != nil {
		return nil, err
	}
	return append(cg, cu...), nil
}

func (app *ClipSight) planSyncConfigToDynamoDBForGroup(ctx context.Context, cfg *Config, silent bool) ([]*ChangeInfo, error) {
	slog.DebugCtx(ctx, "start planSyncConfigToDynamoDBForGroup")
	ctx, cancel := context.WithCancel(ctx)
	ddbGroupCh, backgroundWaiter := app.ListGroups(ctx)
	defer func() {
		cancel()
		backgroundWaiter()
	}()
	changes := make([]*ChangeInfo, 0)
	ddbGroups := make([]*Group, 0)
	for ddbGroup := range ddbGroupCh {
		if !ddbGroup.IsActive() {
			continue
		}
		ddbGroups = append(ddbGroups, ddbGroup)
		group, ok := ListPickup(cfg.Groups, ddbGroup)
		delete := !ok
		if ok {
			delete = !group.IsActive()
		}
		if delete {
			if !silent {
				slog.InfoCtx(ctx, "plan delete group", slog.String("id", ddbGroup.ID))
			}
			changes = append(changes, &ChangeInfo{
				BeforeGroup: ddbGroup,
				AfterGroup:  nil,
			})
			continue
		}
		if !ddbGroup.HasChanges(group) {
			if !silent {
				slog.InfoCtx(ctx, "plan no change group", slog.String("id", ddbGroup.ID))
			}
			continue
		}
		if !silent {
			slog.InfoCtx(ctx, "plan change group", slog.String("group_id", ddbGroup.ID))
		}
		changes = append(changes, &ChangeInfo{
			BeforeGroup: ddbGroup,
			AfterGroup:  group,
		})
	}
	for _, group := range cfg.Groups {
		if !group.IsActive() {
			continue
		}
		if _, ok := ListPickup(ddbGroups, group); ok {
			continue
		}
		if !silent {
			slog.InfoCtx(ctx, "plan create group", slog.String("group_id", group.ID))
		}
		changes = append(changes, &ChangeInfo{
			BeforeGroup: nil,
			AfterGroup:  group,
		})
	}
	return changes, nil
}

func (app *ClipSight) planSyncConfigToDynamoDBForUser(ctx context.Context, cfg *Config, silent bool) ([]*ChangeInfo, error) {
	slog.DebugCtx(ctx, "start planSyncConfigToDynamoDBForUser")
	ctx, cancel := context.WithCancel(ctx)
	ddbUserCh, backgroundWaiter := app.ListUsers(ctx)
	defer func() {
		cancel()
		backgroundWaiter()
	}()
	changes := make([]*ChangeInfo, 0)
	ddbUsers := make([]*User, 0)
	for ddbUser := range ddbUserCh {
		slog.DebugCtx(ctx, "user on ddb", slog.String("id", ddbUser.ID), slog.String("email", ddbUser.Email.String()), slog.String("iam_role_arn", ddbUser.IAMRoleARN))
		if !ddbUser.IsActive() {
			continue
		}
		ddbUsers = append(ddbUsers, ddbUser)
		user, ok := ListPickup(cfg.Users, ddbUser)
		delete := !ok
		if ok {
			delete = !user.IsActive()
		}
		if delete {
			if !silent {
				slog.InfoCtx(ctx, "plan delete user", slog.String("id", ddbUser.ID), slog.String("email", ddbUser.Email.String()), slog.String("iam_role_arn", ddbUser.IAMRoleARN))
			}
			changes = append(changes, &ChangeInfo{
				BeforeUser: ddbUser,
				AfterUser:  nil,
			})
			continue
		}
		if !ddbUser.HasChanges(user) {
			if !silent {
				slog.InfoCtx(ctx, "plan no change", slog.String("id", ddbUser.ID), slog.String("email", ddbUser.Email.String()), slog.String("iam_role_arn", ddbUser.IAMRoleARN))
			}
			continue
		}
		if !silent {
			slog.InfoCtx(ctx, "plan change user", slog.String("id", ddbUser.ID), slog.String("email", ddbUser.Email.String()), slog.String("iam_role_arn", ddbUser.IAMRoleARN))
		}
		changes = append(changes, &ChangeInfo{
			BeforeUser: ddbUser,
			AfterUser:  user,
		})
	}
	for _, user := range cfg.Users {
		if !user.IsActive() {
			continue
		}
		if _, ok := ListPickup(ddbUsers, user); ok {
			continue
		}
		if !silent {
			slog.InfoCtx(ctx, "plan create user", slog.String("id", user.ID), slog.String("email", user.Email.String()), slog.String("iam_role_arn", user.IAMRoleARN))
		}
		changes = append(changes, &ChangeInfo{
			BeforeUser: nil,
			AfterUser:  user,
		})
	}
	return changes, nil
}
