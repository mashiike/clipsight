package clipsight_test

import (
	"testing"
	"time"

	"github.com/mashiike/clipsight"
	"github.com/stretchr/testify/require"
)

func TestReadPermissionFile__SopsEncrypted(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY_FILE", "testdata/key.txt")
	t.Setenv("AWS_REGION", "ap-northeast-1")
	t.Setenv("IAM_ROLE_ARN", "arn:aws:iam::123456789012:role/external")

	pf, err := clipsight.ReadPermissionFile("testdata/permission.encrypted.yaml", true)
	require.NoError(t, err)
	expected := &clipsight.PermissionFile{
		RequiredVersion: pf.RequiredVersion,
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
			},
		},
	}
	require.EqualValues(t, expected, pf)
	require.EqualValues(t, ">=0.0.0", pf.RequiredVersion.String())
}

func TestReadPermissionFile__NoEncrypted(t *testing.T) {
	t.Setenv("AWS_REGION", "ap-northeast-1")
	t.Setenv("IAM_ROLE_ARN", "arn:aws:iam::123456789012:role/external")

	pf, err := clipsight.ReadPermissionFile("testdata/permission.yaml", false)
	require.NoError(t, err)
	expected := &clipsight.PermissionFile{
		RequiredVersion: pf.RequiredVersion,
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
			},
		},
	}
	require.EqualValues(t, expected, pf)
	require.EqualValues(t, ">=0.0.0", pf.RequiredVersion.String())
}
