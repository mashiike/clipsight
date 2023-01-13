package clipsight

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	"github.com/aws/aws-sdk-go-v2/service/quicksight/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/guregu/dynamo"
)

var Version string = "current"

// Clipsight is Application instance for resource lifecycle
type ClipSight struct {
	ddbTableName string
	awsAccountID string
	qs           *quicksight.Client
	sts          *sts.Client
	ddb          *dynamo.DB
}

// New returns initialized application instance
func New(ctx context.Context, ddbTableName string) (*ClipSight, error) {
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
		ddb:          dynamo.New(sess),
	}
	return app, nil
}

// Management table for github.com/mashiike/clipsight
type schema struct {
	HashKey string `dynamo:"HashKey,hash"`
	SortKey string `dynamo:"SortKey,range"`

	Revision int64     `dynamo:"Revision"`
	TTL      time.Time `dynamo:"TTL,unixtime,omitempty"`
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
	log.Println("[debug] try prepare DynaamoDB ")
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
	log.Printf("[debug] try DescribeDashboard(%s, %s)", app.awsAccountID, dashboardID)
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
	log.Printf("[debug] try DescribeDashboardPermissions(%s, %s)", app.awsAccountID, dashboardID)
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
	log.Printf("[debug] try GrantDashboardParmission(%s, %s, %s)", app.awsAccountID, dashboardID, quickSightUserARN)
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
	log.Printf("[debug] try RevokeDashboardParmission(%s, %s, %s)", app.awsAccountID, dashboardID, quickSightUserARN)
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
