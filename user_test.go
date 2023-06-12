package clipsight_test

import (
	"testing"
	"time"

	"github.com/Songmu/flextime"
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
	user.Restrict()
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
	other.Restrict()
	t.Run("nomask", func(t *testing.T) {
		actual, err := user.Diff(other, false)
		require.NoError(t, err)
		g.Assert(t, "diff_change", []byte(actual))
	})
	t.Run("mask", func(t *testing.T) {
		actual, err := user.Diff(other, true)
		require.NoError(t, err)
		g.Assert(t, "diff_change_mask", []byte(actual))
	})
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
	user.Restrict()
	t.Run("nomask", func(t *testing.T) {
		actual, err := user.Diff(nil, false)
		require.NoError(t, err)
		g.Assert(t, "diff_add", []byte(actual))
	})
	t.Run("mask", func(t *testing.T) {
		actual, err := user.Diff(nil, true)
		require.NoError(t, err)
		g.Assert(t, "diff_add_mask", []byte(actual))
	})
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
	other.Restrict()
	t.Run("nomask", func(t *testing.T) {
		actual, err := user.Diff(other, false)
		require.NoError(t, err)
		g.Assert(t, "diff_delete", []byte(actual))
	})
	t.Run("mask", func(t *testing.T) {
		actual, err := user.Diff(other, true)
		require.NoError(t, err)
		g.Assert(t, "diff_delete_mask", []byte(actual))
	})
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
	require.True(t, user.EqualDashboardPermissions(other))
}

func TestUser__Equal__MissmachePermissions(t *testing.T) {
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
	require.False(t, user.EqualDashboardPermissions(other))
}

func TestUser__DiffPermissions(t *testing.T) {
	restore := flextime.Fix(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
	defer restore()
	user := &clipsight.User{
		Email:      "hoge@example.com",
		Region:     "ap-northeast-1",
		Namespace:  "external",
		IAMRoleARN: "arn:aws:iam::123456789012:role/external",
		Dashboards: []*clipsight.Dashboard{
			{
				DashboardID: "12345678-1234-1234-1234-123456789012",
			},
			{
				DashboardID: "56789012-3456-7890-1234-567890123456", //need revoke

			},
			{
				DashboardID: "34567890-1234-5678-9012-345678901234", //need grant for expire extend
				Expire:      time.Time(time.Date(2021, 1, 2, 0, 0, 0, 0, time.UTC)),
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
			},
			{
				DashboardID: "90123456-7890-1234-5678-901234567890", //need grant
			},
			{
				DashboardID: "34567890-1234-5678-9012-345678901234", //need grant for expire extend
				Expire:      time.Time(time.Date(2022, 1, 2, 0, 0, 0, 0, time.UTC)),
			},
			{
				DashboardID: "76543210-4321-8765-4321-876543210987", //expired ignore change
				Expire:      time.Time(time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC)),
			},
		},
		Enabled: true,
	}
	grantGot, revokeGot := user.DiffPermissions(other)
	grantWant := []*clipsight.Dashboard{
		{
			DashboardID: "90123456-7890-1234-5678-901234567890",
		},
		{
			DashboardID: "34567890-1234-5678-9012-345678901234", //need grant for expire extend
			Expire:      time.Time(time.Date(2022, 1, 2, 0, 0, 0, 0, time.UTC)),
		},
	}
	require.EqualValues(t, grantWant, grantGot, "grant")
	revokeWant := []*clipsight.Dashboard{
		{
			DashboardID: "56789012-3456-7890-1234-567890123456",
		},
	}
	require.EqualValues(t, revokeWant, revokeGot, "revoke")
}
