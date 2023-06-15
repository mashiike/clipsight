package clipsight

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Songmu/flextime"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	"github.com/aws/aws-sdk-go-v2/service/quicksight/types"
	"github.com/guregu/dynamo"
	"github.com/pmezard/go-difflib/difflib"
	"golang.org/x/exp/slog"
)

type Email string

func (email Email) Validate() error {
	if email == "" {
		return errors.New("email is empty")
	}
	_, err := mail.ParseAddress(string(email))
	return err
}
func (email Email) String() string {
	return string(email)
}

type User struct {
	schema
	ID                string                `dynamodb:"ID" yaml:"id" json:"id"`
	Email             Email                 `dynamodb:"Email" yaml:"email" json:"email"`
	Namespace         string                `dynamodb:"Namespace" yaml:"namespace" json:"namespace"`
	IAMRoleARN        string                `dynamodb:"IAMRoleARN" yaml:"iam_role_arn" json:"iam_role_arn"`
	Region            string                `dynamodb:"Region" yaml:"region" json:"region"`
	Dashboards        []*Dashboard          `dynamodb:"Dashboards" yaml:"dashboards" json:"dashboards"`
	Groups            []UserGroupMembership `dynamodb:"Groups" yaml:"groups" json:"groups"`
	Enabled           bool                  `dynamodb:"Enabled" yaml:"enabled" json:"enabled"`
	CreatedAt         time.Time             `dynamodb:"CreatedAt,unixtime" yaml:"-" json:"-"`
	UpdatedAt         time.Time             `dynamodb:"UpdatedAt,unixtime" yaml:"-" json:"-"`
	QuickSightUserARN string                `dynamodb:"QuickSightUserARN" yaml:"-" json:"-"`
}

type UserGroupMembership string

type Dashboard struct {
	DashboardID string    `dynamodb:"DashboardID" yaml:"dashboard_id" json:"dashboard_id"`
	Expire      time.Time `dynamodb:"Expire,unixtime" yaml:"expire" json:"expire,omitempty"`
}

var (
	emailHashSolt     string
	emailHashSoltOnce sync.Once
)

func (u *User) Restrict() error {
	if u.ID == "" {
		emailHashSoltOnce.Do(func() {
			emailHashSolt = os.Getenv("CLIPSIGHT_EMAIL_HASH_SOLT")
			if emailHashSolt == "" {
				emailHashSolt = "clipsight"
			}
		})
		u.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(emailHashSolt+u.Email.String())))
	}
	if u.Email == "" {
		return errors.New("email is required")
	}
	if err := u.Email.Validate(); err != nil {
		return fmt.Errorf("email is invalid: %w", err)
	}
	if u.Namespace == "" {
		u.Namespace = "default"
	}
	if u.IAMRoleARN == "" {
		return errors.New("iam_role_arn is required")
	}
	if u.Region == "" {
		u.Region = os.Getenv("AWS_REGION")
		if u.Region == "" {
			return errors.New("region is required")
		}
	}
	u.FillKey()
	for i, d := range u.Dashboards {
		if d.DashboardID == "" {
			return fmt.Errorf("dashboards[%d].dashboard_id is required", i)
		}
	}
	return nil
}

func (u *User) FillKey() *User {
	u.HashKey = "USER"
	u.SortKey = "USER:" + u.Email.String()
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
			u.Dashboards[i].Expire = expire
			return
		}
	}
	u.Dashboards = append(u.Dashboards, &Dashboard{
		DashboardID: *dashboard.DashboardId,
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

func (u *User) Diff(user *User, maskEmail bool) (string, error) {
	current, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return "", err
	}
	currentStr := string(current)
	other, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return "", err
	}
	otherStr := string(other)
	if maskEmail {
		var email Email
		if u != nil {
			email = u.Email
		} else {
			email = user.Email
		}
		currentStr = strings.ReplaceAll(currentStr, email.String(), "********")
		otherStr = strings.ReplaceAll(otherStr, email.String(), "********")
	}
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

func (u *User) GetDashboard(id string) (*Dashboard, bool) {
	if u == nil {
		return nil, false
	}
	for _, d := range u.Dashboards {
		if d.DashboardID == id {
			if !d.IsVisible() {
				return nil, false
			}
			return d, true
		}
	}
	return nil, false
}

func (u *User) DiffPermissions(other *User) ([]*Dashboard, []*Dashboard) {
	var a []*Dashboard
	if u != nil {
		a = make([]*Dashboard, 0, len(u.Dashboards))
		for _, d := range u.Dashboards {
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

func (u *User) DiffGroups(other *User) ([]UserGroupMembership, []UserGroupMembership) {
	added, _, removed := ListDiff(u.Groups, other.Groups)
	return added, removed
}

func (u *User) Equals(user *User) bool {
	if u == nil || user == nil {
		return u == nil && user == nil
	}
	if u.Email != user.Email {
		return false
	}
	if u.Namespace != user.Namespace {
		return false
	}
	if u.IAMRoleARN != user.IAMRoleARN {
		return false
	}
	if u.Region != user.Region {
		return false
	}
	if u.TTL != user.TTL {
		return false
	}
	return u.Enabled == user.Enabled
}

func (u *User) EqualIdentifiers(user *User) bool {
	if u == nil || user == nil {
		return u == nil && user == nil
	}
	return u.Email == user.Email && u.IAMRoleARN == user.IAMRoleARN
}

func (u *User) EqualDashboardPermissions(user *User) bool {
	if u == nil || user == nil {
		return u == nil && user == nil
	}
	if len(u.Dashboards) != len(user.Dashboards) {
		return false
	}
	// check dashboard element match by DashboardID
	grant, revoke := u.DiffPermissions(user)
	if len(grant) > 0 || len(revoke) > 0 {
		return false
	}
	return true
}

func (u *User) EqualGroups(user *User) bool {
	if u == nil || user == nil {
		return u == nil && user == nil
	}
	if len(u.Groups) != len(user.Groups) {
		return false
	}
	assigne, unassign := u.DiffGroups(user)
	if len(assigne) > 0 || len(unassign) > 0 {
		return false
	}
	return true
}

func (u *User) HasChanges(user *User) bool {
	return !u.Equals(user) || !u.EqualDashboardPermissions(user) || !u.EqualGroups(user)
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
	return flextime.Now().UnixNano() < d.Expire.UnixNano()
}

func (d *Dashboard) Equals(other *Dashboard) bool {
	if d == nil || other == nil {
		return d == nil && other == nil
	}
	if d.DashboardID != other.DashboardID {
		return false
	}
	return d.Expire.Equal(other.Expire)
}

func (d *Dashboard) EqualIdentifiers(other *Dashboard) bool {
	if d == nil || other == nil {
		return d == nil && other == nil
	}
	if d.DashboardID != other.DashboardID {
		return false
	}
	return true
}

func (m UserGroupMembership) Equals(other UserGroupMembership) bool {
	return m.EqualIdentifiers(other)
}

func (m UserGroupMembership) EqualIdentifiers(other UserGroupMembership) bool {
	return m == other
}

func (app *ClipSight) GetUser(ctx context.Context, email Email) (*User, bool, error) {
	user := NewUser(email)
	if err := app.ddbTable().Get("HashKey", user.HashKey).Range("SortKey", dynamo.Equal, user.SortKey).Limit(1).OneWithContext(ctx, user); err != nil {
		if strings.Contains(err.Error(), "no item found") {
			return user, false, nil
		}
		return nil, false, err
	}
	return user, true, nil
}

func (app *ClipSight) SaveUser(ctx context.Context, user *User) error {
	if err := user.Restrict(); err != nil {
		return err
	}
	rev := user.Revision
	user.Revision++
	if user.CreatedAt.IsZero() {
		user.CreatedAt = flextime.Now()
	}
	user.UpdatedAt = flextime.Now()
	putOp := app.ddbTable().Put(user)
	slog.DebugCtx(ctx, "update user item", slog.String("email", user.Email.String()), slog.Int64("current_rivision", rev), slog.Int64("next_revision", user.Revision))
	if rev == 0 {
		putOp = putOp.If("attribute_not_exists(HashKey) AND attribute_not_exists(SortKey)")
	} else if rev > 0 {
		putOp = putOp.If("Revision = ?", rev)
	}
	return putOp.RunWithContext(ctx)
}

func (app *ClipSight) DeleteUser(ctx context.Context, user *User) error {
	return app.ddbTable().Delete("HashKey", user.HashKey).Range("SortKey", user.SortKey).RunWithContext(ctx)
}

func (app *ClipSight) GrantDashboardToUser(ctx context.Context, user *User, dashboardID string, expire time.Time) error {
	dashboard, exists, err := app.DescribeDashboard(ctx, dashboardID)
	if err != nil {
		return fmt.Errorf("describe quicksight user: %w", err)
	}
	if !exists {
		return fmt.Errorf("dashboard `%s` not found in %s account", dashboardID, app.awsAccountID)
	}
	slog.InfoCtx(ctx, "grant dashboard permission", slog.String("user_id", user.ID), slog.String("dashboard_name", *dashboard.Name), slog.String("dashboard_arn", *dashboard.Arn), slog.String("quick_sight_user_arn", user.QuickSightUserARN))
	if err := app.GrantDashboardParmission(ctx, dashboardID, user.QuickSightUserARN); err != nil {
		return fmt.Errorf("grant dashboard permission: %w", err)
	}

	user.GrantDashboard(dashboard, expire)
	slog.DebugCtx(ctx, "try save user", slog.String("user_id", user.ID), slog.String("email", user.Email.String()))
	if err := app.SaveUser(ctx, user); err != nil {
		return fmt.Errorf("save user: %w", err)
	}
	return nil
}

func (app *ClipSight) RevokeDashboardFromUser(ctx context.Context, user *User, dashboardID string) error {
	if user.RevokeDashboard(dashboardID) {
		slog.DebugCtx(ctx, "try save user", slog.String("user_id", user.ID), slog.String("email", user.Email.String()))
		if err := app.SaveUser(ctx, user); err != nil {
			return fmt.Errorf("save user: %w", err)
		}
	}
	slog.DebugCtx(ctx, "try revoke dashboard permission", slog.String("user_id", user.ID), slog.String("dashboard_id", dashboardID), slog.String("quick_sight_user_arn", user.QuickSightUserARN))
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
	slog.DebugCtx(ctx, "try DescribeQuicksightUser", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("quick_sight_user_name", userName))
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
	slog.DebugCtx(ctx, "try RegisterQuicksightUser", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("quick_sight_user_name", userName))
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

func (app *ClipSight) DeleteQuickSightUser(ctx context.Context, user *User) error {
	_, exists, err := app.DescribeQuickSightUser(ctx, user)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	userName, err := user.QuickSightUserName()
	if err != nil {
		return err
	}
	slog.DebugCtx(ctx, "try DeleteQuicksightUser", slog.String("user_id", user.ID), slog.String("email", user.Email.String()), slog.String("quick_sight_user_name", userName))
	output, err := app.qs.DeleteUser(ctx, &quicksight.DeleteUserInput{
		AwsAccountId: aws.String(app.awsAccountID),
		Namespace:    aws.String(user.Namespace),
		UserName:     aws.String(userName),
	})
	if err != nil {
		return err
	}
	if output.Status != http.StatusOK {
		return fmt.Errorf("HTTP Status %d", output.Status)
	}
	return nil
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

func (app *ClipSight) ListUsers(ctx context.Context) (<-chan *User, func()) {
	ch := make(chan *User, 100)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer func() {
			slog.DebugCtx(ctx, "list users done")
			wg.Done()
		}()
		slog.DebugCtx(ctx, "list users start")
		iter := app.ddbTable().Scan().Filter("'HashKey' = ?", "USER").Iter()
		for {
			var user User
			isContinue := iter.NextWithContext(ctx, &user)
			if !isContinue {
				break
			}
			ch <- &user
		}
		if err := iter.Err(); err != nil {
			slog.ErrorCtx(ctx, "list users error", "detail", err)
		}
		close(ch)
	}()
	return ch, wg.Wait
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
