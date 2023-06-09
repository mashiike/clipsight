package clipsight_test

import (
	"testing"
	"time"

	"github.com/mashiike/clipsight"
	"github.com/sebdah/goldie/v2"
	"github.com/stretchr/testify/require"
)

func TestUser__Diff_Change(t *testing.T) {
	g := goldie.New(t,
		goldie.WithFixtureDir("testdata/user/"),
		goldie.WithNameSuffix(".golden"),
	)
	user := &clipsight.User{
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
	}
	other := &clipsight.User{
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
	}
	actual, err := user.Diff(other)
	require.NoError(t, err)
	g.Assert(t, "diff_change", []byte(actual))
	require.False(t, user.Equals(other))
}

func TestUser__Diff_Add(t *testing.T) {
	g := goldie.New(t,
		goldie.WithFixtureDir("testdata/user/"),
		goldie.WithNameSuffix(".golden"),
	)
	user := &clipsight.User{
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
	}
	actual, err := user.Diff(nil)
	require.NoError(t, err)
	g.Assert(t, "diff_add", []byte(actual))
	require.False(t, user.Equals(nil))
}

func TestUser__Diff_Delete(t *testing.T) {
	g := goldie.New(t,
		goldie.WithFixtureDir("testdata/user/"),
		goldie.WithNameSuffix(".golden"),
	)
	user := (*clipsight.User)(nil)
	other := &clipsight.User{
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
	}
	actual, err := user.Diff(other)
	require.NoError(t, err)
	g.Assert(t, "diff_delete", []byte(actual))
	require.False(t, user.Equals(other))
}

func TestUser__Equal__Same(t *testing.T) {
	user := &clipsight.User{
		Email:      "hoge@example.com",
		Region:     "ap-northeast-1",
		Namespace:  "external",
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
		Enabled:           true,
		CreatedAt:         time.Time(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
		UpdatedAt:         time.Time(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
		QuickSightUserARN: "arn:aws:quicksight:ap-northeast-1:123456789012:default",
	}
	other := &clipsight.User{
		Email:      "hoge@example.com",
		Region:     "ap-northeast-1",
		Namespace:  "external",
		IAMRoleARN: "arn:aws:iam::123456789012:role/external",
		Dashboards: []*clipsight.Dashboard{
			{
				DashboardID: "00000000-0000-0000-0000-000000000000",
			},
			{
				DashboardID: "12345678-1234-1234-1234-123456789012",
				Expire:      time.Time(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
		Enabled: true,
	}
	require.True(t, user.Equals(other))
}
