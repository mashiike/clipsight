package clipsight

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	"github.com/aws/aws-sdk-go-v2/service/quicksight/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/guregu/dynamo"
	gv "github.com/hashicorp/go-version"
	"go.mozilla.org/sops/v3/decrypt"
	"gopkg.in/yaml.v3"
)

var Version string = "current"

// Clipsight is Application instance for resource lifecycle
type ClipSight struct {
	ddbTableName string
	awsAccountID string
	users        []*User
	qs           *quicksight.Client
	sts          *sts.Client
	ddb          *dynamo.DB
}

// New returns initialized application instance
func New(ctx context.Context, opt *CLI) (*ClipSight, error) {
	awsCfgV2, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	stsClient := sts.NewFromConfig(awsCfgV2)
	getCallerIdentityOutput, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	quicksightClient := quicksight.NewFromConfig(awsCfgV2)
	if opt.PermissionFile != "" {
		return newWithPermissionFile(ctx, opt, stsClient, quicksightClient, *getCallerIdentityOutput.Account)
	} else if opt.DDBTable != "" {
		return newWithDDB(ctx, opt, stsClient, quicksightClient, *getCallerIdentityOutput.Account)
	} else {
		return nil, errors.New("permission file or ddb table name is required")
	}
}

func newWithPermissionFile(ctx context.Context, opt *CLI, stsClient *sts.Client, quicksightClient *quicksight.Client, awsAccountID string) (*ClipSight, error) {
	log.Println("[info] permission file mode")
	return nil, errors.New("permission file mode is not implemented yet")

}

type VersionConstraint struct {
	gv.Constraints
}

func (c *VersionConstraint) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	constraints, err := gv.NewConstraint(s)
	if err != nil {
		return err
	}
	c.Constraints = constraints
	return nil
}

type PermissionFile struct {
	RequiredVersion VersionConstraint `yaml:"required_version"`
	Users           []*User           `yaml:"users"`
}

func ReadPermissionFile(filename string, sopsEncrypted bool) (*PermissionFile, error) {
	var bs []byte
	var err error
	if sopsEncrypted {
		bs, err = decrypt.File(filename, "yaml")
	} else {
		bs, err = os.ReadFile(filename)
	}
	if err != nil {
		return nil, err
	}
	tpl, err := template.New("permission_file").Funcs(template.FuncMap{
		"must_env": func(key string) (string, error) {
			if v, ok := os.LookupEnv(key); ok {
				return v, nil
			}
			return "", fmt.Errorf("environment variable %s is not defined", key)
		},
		"env": func(key string) string {
			return os.Getenv(key)
		},
	}).Parse(string(bs))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, nil); err != nil {
		return nil, err
	}
	decoder := yaml.NewDecoder(&buf)
	decoder.KnownFields(true)
	var pf PermissionFile
	if err := decoder.Decode(&pf); err != nil {
		return nil, err
	}
	for _, u := range pf.Users {
		if u.Region == "" {
			u.Region = os.Getenv("AWS_REGION")
		}
		if u.Namespace == "" {
			u.Namespace = "default"
		}
	}
	return &pf, nil
}

func newWithDDB(ctx context.Context, opt *CLI, stsClient *sts.Client, quicksightClient *quicksight.Client, awsAccountID string) (*ClipSight, error) {
	log.Println("[info] ddb table mode")
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}
	app := &ClipSight{
		ddbTableName: opt.DDBTable,
		awsAccountID: awsAccountID,
		qs:           quicksightClient,
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

func (app *ClipSight) isDDBMode() bool {
	return app.ddb != nil
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
