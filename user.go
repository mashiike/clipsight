package clipsight

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	"github.com/aws/aws-sdk-go-v2/service/quicksight/types"
	"github.com/google/uuid"
	"github.com/guregu/dynamo"
)

type Email string

func (email Email) Validate() error {
	_, err := mail.ParseAddress(string(email))
	return err
}
func (email Email) String() string {
	return string(email)
}

type User struct {
	schema
	ID                string       `dynamodb:"ID,hash" json:"id" yaml:"id"`
	Email             Email        `dynamodb:"Email" json:"email" yaml:"email"`
	Namespace         string       `dynamodb:"Namespace" json:"namespace" yaml:"namespace"`
	IAMRoleARN        string       `dynamodb:"IAMRoleARN" json:"iam_role_arn" yaml:"iam_role_arn"`
	Region            string       `dynamodb:"Region" json:"region" yaml:"region"`
	Dashboards        []*Dashboard `dynamodb:"Dashboards" json:"dashboards" yaml:"dashboards"`
	Enabled           bool         `dynamodb:"Enabled" json:"-" yaml:"-"`
	CreatedAt         time.Time    `dynamodb:"CreatedAt,unixtime" json:"-" yaml:"-"`
	UpdatedAt         time.Time    `dynamodb:"UpdatedAt,unixtime" json:"-" yaml:"-"`
	QuickSightUserARN string       `dynamodb:"QuickSightUserARN" json:"-" yaml:"-"`
}

type Dashboard struct {
	Name        string
	DashboardID string    `dynamodb:"DashboardID" json:"dashboard_id" yaml:"dashboard_id"`
	Expire      time.Time `dynamodb:"Expire,unixtime"`
}

func (u *User) FillKey() *User {
	u.HashKey = "USER"
	u.SortKey = "USER:" + u.Email.String()
	if id, err := uuid.NewRandom(); err == nil {
		u.ID = id.String()
	}
	return u
}

func (u *User) IsNew() bool {
	return u.Revision == 0
}

func (u *User) QuickSightUserName() (string, error) {
	roleName, err := GetIAMRoleName(u.IAMRoleARN)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s", roleName, u.Email), nil
}

func (u *User) GrantDashboard(dashboard *types.Dashboard, expire time.Time) {
	for i, d := range u.Dashboards {
		if d.DashboardID == *dashboard.DashboardId {
			u.Dashboards[i].Name = *dashboard.Name
			u.Dashboards[i].Expire = expire
			return
		}
	}
	u.Dashboards = append(u.Dashboards, &Dashboard{
		DashboardID: *dashboard.DashboardId,
		Name:        *dashboard.Name,
		Expire:      expire,
	})
}

func (u *User) RevokeDashboard(dashboardID string) bool {
	for i, d := range u.Dashboards {
		if d.DashboardID == dashboardID {
			u.Dashboards = append(u.Dashboards[:i], u.Dashboards[i+1:]...)
			return true
		}
	}
	return false
}

func (u *User) IsActive() bool {
	if u.schema.IsExpire() {
		return false
	}
	return u.Enabled
}

func NewUser(email Email) *User {
	return (&User{
		Email: email,
	}).FillKey()
}

func (d *Dashboard) IsVisible() bool {
	if d.Expire.IsZero() {
		return true
	}
	return time.Now().UnixNano() < d.Expire.UnixNano()
}

func (app *ClipSight) GetUser(ctx context.Context, email Email) (*User, bool, error) {
	if app.isDDBMode() {
		user := NewUser(email)
		if err := app.ddbTable().Get("HashKey", user.HashKey).Range("SortKey", dynamo.Equal, user.SortKey).Limit(1).OneWithContext(ctx, user); err != nil {
			if strings.Contains(err.Error(), "no item found") {
				return user, false, nil
			}
			return nil, false, err
		}
		return user, true, nil
	}
	user, ok := app.users[email.String()]
	if !ok {
		return NewUser(email), false, nil
	}
	return user, true, nil
}

func (app *ClipSight) SaveUser(ctx context.Context, user *User) error {
	if !app.isDDBMode() {
		return errors.New("no ddb table mode not supported")
	}
	user = user.FillKey()
	rev := user.Revision
	user.Revision++
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}
	user.UpdatedAt = time.Now()
	putOp := app.ddbTable().Put(user)
	log.Printf("[debug] update user item (email:%s rev:%d -> %d", user.Email, rev, user.Revision)
	if rev == 0 {
		putOp = putOp.If("attribute_not_exists(HashKey) AND attribute_not_exists(SortKey)")
	} else if rev > 0 {
		putOp = putOp.If("Revision = ?", rev)
	}
	return putOp.RunWithContext(ctx)
}

func (app *ClipSight) GrantDashboardToUser(ctx context.Context, user *User, dashboardID string, expire time.Time) error {
	dashboard, exists, err := app.DescribeDashboard(ctx, dashboardID)
	if err != nil {
		return fmt.Errorf("describe quicksight user: %w", err)
	}
	if !exists {
		return fmt.Errorf("dashboard `%s` not found in %s account", dashboardID, app.awsAccountID)
	}
	log.Printf("[info] dashboard name `%s`, arn is `%s`", *dashboard.Name, *dashboard.Arn)
	log.Printf("[debug] try grant permission `%s`, user arn is `%s`", *dashboard.Name, user.QuickSightUserARN)
	if err := app.GrantDashboardParmission(ctx, dashboardID, user.QuickSightUserARN); err != nil {
		return fmt.Errorf("grant dashboard permission: %w", err)
	}

	user.GrantDashboard(dashboard, expire)
	log.Println("[debug] try save user", user.Email)
	if err := app.SaveUser(ctx, user); err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	return nil
}

func (app *ClipSight) RevokeDashboardFromUser(ctx context.Context, user *User, dashboardID string) error {
	if user.RevokeDashboard(dashboardID) {
		log.Println("[debug] try save user", user.Email)
		if err := app.SaveUser(ctx, user); err != nil {
			return fmt.Errorf("save user: %w", err)
		}
	}
	log.Printf("[debug] try revoke permission `%s`, user arn is `%s`", dashboardID, user.QuickSightUserARN)
	if err := app.RevokeDashboardParmission(ctx, dashboardID, user.QuickSightUserARN); err != nil {
		return fmt.Errorf("revoke dashboard permission: %w", err)
	}

	return nil
}

func (app *ClipSight) DescribeQuickSightUser(ctx context.Context, user *User) (*types.User, bool, error) {
	userName, err := user.QuickSightUserName()
	if err != nil {
		return nil, false, err
	}
	log.Printf("[debug] try DescribeQuicksightUser(%s, %s, %s)", app.awsAccountID, user.Namespace, userName)
	output, err := app.qs.DescribeUser(ctx, &quicksight.DescribeUserInput{
		AwsAccountId: aws.String(app.awsAccountID),
		Namespace:    aws.String(user.Namespace),
		UserName:     aws.String(userName),
	})
	if err != nil {
		var rnf *types.ResourceNotFoundException
		if !errors.As(err, &rnf) {
			return nil, false, err
		}
		return &types.User{
			Active:   false,
			UserName: aws.String(userName),
		}, false, nil
	}
	if output.Status != http.StatusOK {
		return nil, false, fmt.Errorf("HTTP Status %d", output.Status)
	}
	return output.User, true, nil
}

func (app *ClipSight) RegisterQuickSightUser(ctx context.Context, user *User) (*types.User, error) {
	userName, err := user.QuickSightUserName()
	if err != nil {
		return nil, err
	}
	log.Printf("[debug] try RegisterQuicksightUser(%s, %s, %s)", app.awsAccountID, user.Namespace, userName)
	output, err := app.qs.RegisterUser(ctx, &quicksight.RegisterUserInput{
		AwsAccountId: aws.String(app.awsAccountID),
		Namespace:    aws.String(user.Namespace),
		Email:        aws.String(user.Email.String()),
		IdentityType: types.IdentityTypeIam,
		UserRole:     types.UserRoleReader,
		IamArn:       aws.String(user.IAMRoleARN),
		SessionName:  aws.String(user.Email.String()),
	})
	if err != nil {
		return nil, err
	}
	if output.Status != http.StatusCreated {
		return nil, fmt.Errorf("HTTP Status %d", output.Status)
	}
	return output.User, nil
}

func (app *ClipSight) NewQuickSightClientWithUser(ctx context.Context, user *User) (*quicksight.Client, error) {
	awsCfgV2, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	creds := stscreds.NewAssumeRoleProvider(app.sts, user.IAMRoleARN, func(opts *stscreds.AssumeRoleOptions) {
		opts.RoleSessionName = user.Email.String()
		opts.Duration = 900 * time.Second
	})
	awsCfgV2.Credentials = creds
	return quicksight.NewFromConfig(awsCfgV2), nil
}

type contextKey string

var userContextKey contextKey = "__clipsight__user"

// WithUser appends context into clipsight user instance
func WithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userContextKey).(*User)
	return user, ok
}
