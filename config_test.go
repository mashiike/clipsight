package clipsight_test

import (
	"sort"
	"testing"
	"time"

	"github.com/mashiike/clipsight"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY_FILE", "testdata/key.txt")
	t.Setenv("AWS_REGION", "ap-northeast-1")
	t.Setenv("IAM_ROLE_ARN", "arn:aws:iam::123456789012:role/external")
	cfg, err := clipsight.LoadConfig("testdata/config/")
	require.NoError(t, err)
	require.EqualValues(t, ">=0.0.0", cfg.RequiredVersion.String())
	expected := &clipsight.Config{
		RequiredVersion: cfg.RequiredVersion,
		Users: []*clipsight.User{
			{
				Email:      "hoge@example.com",
				Region:     "ap-northeast-1",
				Namespace:  "external",
				IAMRoleARN: "arn:aws:iam::123456789012:role/external",
				Dashboards: []*clipsight.Dashboard{
					{
						DashboardID: "12345678-1234-1234-1234-123456789012",
						Expire:      time.Time(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
					},
				},
				Enabled: true,
			},
			{
				Email:      "fuga@example.com",
				Region:     "ap-northeast-1",
				Namespace:  "default",
				IAMRoleARN: "arn:aws:iam::123456789012:role/external",
				Dashboards: []*clipsight.Dashboard{
					{
						DashboardID: "12345678-1234-1234-1234-123456789012",
						Expire:      time.Time(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
					},
					{
						DashboardID: "00000000-0000-0000-0000-000000000000",
					},
				},
				Enabled: true,
			},
			{
				Email:      "tora@example.com",
				Region:     "ap-northeast-1",
				Namespace:  "external",
				IAMRoleARN: "arn:aws:iam::123456789012:role/external",
				Dashboards: []*clipsight.Dashboard{
					{
						DashboardID: "12345678-1234-1234-1234-123456789012",
						Expire:      time.Time(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
					},
				},
				Groups: []clipsight.UserGroupMembership{
					"admin",
				},
				Enabled: true,
			},
			{
				Email:      "piyo@example.com",
				Region:     "ap-northeast-1",
				Namespace:  "default",
				IAMRoleARN: "arn:aws:iam::123456789012:role/external",
				Dashboards: []*clipsight.Dashboard{
					{
						DashboardID: "12345678-1234-1234-1234-123456789012",
						Expire:      time.Time(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
					},
					{
						DashboardID: "00000000-0000-0000-0000-000000000000",
					},
				},
				Enabled: true,
			},
		},
	}
	sort.Slice(cfg.Users, func(i, j int) bool {
		return cfg.Users[i].Email < cfg.Users[j].Email
	})
	for _, u := range expected.Users {
		u.Restrict()
	}
	sort.Slice(expected.Users, func(i, j int) bool {
		return expected.Users[i].Email < expected.Users[j].Email
	})
	require.EqualValues(t, expected, cfg)
}
