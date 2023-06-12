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

func (app *ClipSight) GrantDashboardParmission(ctx context.Context, dashboardID string, quickSightUserARN string) error {
	permissions, err := app.DescribeDashboardParmissions(ctx, dashboardID)
	if err != nil {
		return fmt.Errorf("permission check: %w", err)
	}

	for _, permission := range permissions {
		if *permission.Principal == quickSightUserARN {
			return nil
		}
	}
	slog.DebugCtx(ctx, "try GrantDashboardParmission(%s, %s, %s)", slog.String("aws_account_id", app.awsAccountID), slog.String("dashboard_id", dashboardID), slog.String("quick_sight_user_arn", quickSightUserARN))
	output, err := app.qs.UpdateDashboardPermissions(ctx, &quicksight.UpdateDashboardPermissionsInput{
		AwsAccountId: aws.String(app.awsAccountID),
		DashboardId:  aws.String(dashboardID),
		GrantPermissions: []types.ResourcePermission{
			{
				Principal: aws.String(quickSightUserARN),
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

func (app *ClipSight) RevokeDashboardParmission(ctx context.Context, dashboardID string, quickSightUserARN string) error {
	permissions, err := app.DescribeDashboardParmissions(ctx, dashboardID)
	if err != nil {
		return fmt.Errorf("permission check: %w", err)
	}

	revokePermissions := make([]types.ResourcePermission, 0)
	for _, permission := range permissions {
		if *permission.Principal == quickSightUserARN {
			revokePermissions = append(revokePermissions, permission)
		}
	}
	if len(revokePermissions) == 0 {
		return nil
	}
	slog.DebugCtx(ctx, "try RevokeDashboardParmission(%s, %s, %s)", slog.String("aws_account_id", app.awsAccountID), slog.String("dashboard_id", dashboardID), slog.String("quick_sight_user_arn", quickSightUserARN))
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
	Before *User
	After  *User
}

func (c *ChangeInfo) String() string {
	return c.diffString(true)
}

func (c *ChangeInfo) UnmaskString() string {
	return c.diffString(false)
}

func (c *ChangeInfo) diffString(mask bool) string {
	var builder strings.Builder
	builder.WriteString("QuickSightUser: ")
	var userName string
	if c.Before != nil {
		userName, _ = c.Before.QuickSightUserName()
	}
	if userName == "" && c.After != nil {
		userName, _ = c.After.QuickSightUserName()
	}
	builder.WriteString(userName)
	builder.WriteString("\n")
	diffStr, err := c.Before.Diff(c.After, mask)
	if err != nil {
		fmt.Fprintf(&builder, "diff print error: %s\n", err)
	} else {
		builder.WriteString(diffStr)
	}
	builder.WriteString("\n")
	return builder.String()
}

func (c *ChangeInfo) NeedRegister() bool {
	if c.After == nil {
		return false
	}
	return !c.Before.Equals(c.After)
}

func (c *ChangeInfo) NeedPermissionModify() bool {
	return !c.Before.EqualDashboardPermissions(c.After)
}

func (c *ChangeInfo) NeedDeregister() bool {
	return c.After == nil
}

func (app *ClipSight) PlanSyncConfigToDynamoDB(ctx context.Context, cfg *Config, silent bool) ([]*ChangeInfo, error) {
	slog.DebugCtx(ctx, "start PlanSyncConfigToDynamoDB")
	usersByQuickSightUserName := make(map[string]*User)
	for _, user := range cfg.Users {
		userName, err := user.QuickSightUserName()
		if err != nil {
			return nil, fmt.Errorf("invalid user: %w", err)
		}
		usersByQuickSightUserName[userName] = user
	}
	ctx, cancel := context.WithCancel(ctx)
	ddbUserCh, backgroundWaiter := app.ListUsers(ctx)
	defer func() {
		cancel()
		backgroundWaiter()
	}()
	changes := make([]*ChangeInfo, 0)
	exists := make(map[string]bool, len(cfg.Users))
	for ddbUser := range ddbUserCh {
		if !ddbUser.IsActive() {
			continue
		}
		userName, err := ddbUser.QuickSightUserName()
		if err != nil {
			return nil, err
		}
		exists[userName] = true
		user, ok := usersByQuickSightUserName[userName]
		if !ok {
			if !silent {
				slog.InfoCtx(ctx, "plan delete user", slog.String("id", ddbUser.ID), slog.String("quick_sight_user_name", userName))
			}
			changes = append(changes, &ChangeInfo{
				Before: ddbUser,
				After:  nil,
			})
			continue
		}
		if ddbUser.Equals(user) && ddbUser.EqualDashboardPermissions(user) {
			continue
		}
		if !silent {
			slog.InfoCtx(ctx, "plan change user", slog.String("id", ddbUser.ID), slog.String("quick_sight_user_name", userName))
		}
		changes = append(changes, &ChangeInfo{
			Before: ddbUser,
			After:  user,
		})
	}
	for _, user := range cfg.Users {
		if !user.IsActive() {
			continue
		}
		userName, err := user.QuickSightUserName()
		if err != nil {
			return nil, fmt.Errorf("invalid user: %w", err)
		}
		if exists[userName] {
			continue
		}
		if !silent {
			slog.InfoCtx(ctx, "plan create user", slog.String("id", user.ID), slog.String("quick_sight_user_name", userName))
		}
		changes = append(changes, &ChangeInfo{
			Before: nil,
			After:  user,
		})
	}
	return changes, nil
}
