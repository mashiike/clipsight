package clipsight_test

import (
	"testing"
	"time"

	"github.com/mashiike/clipsight"
	"github.com/sebdah/goldie/v2"
	"github.com/stretchr/testify/require"
)

func TestGroup__Diff_Change(t *testing.T) {
	g := goldie.New(t,
		goldie.WithFixtureDir("testdata/group/"),
		goldie.WithNameSuffix(".golden"),
	)
	group := &clipsight.Group{
		ID:        "hoge",
		Region:    "ap-northeast-1",
		Namespace: "external",
		Dashboards: []*clipsight.Dashboard{
			{
				DashboardID: "12345678-1234-1234-1234-123456789012",
				Expire:      time.Time(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
		Enabled: true,
	}
	group.Restrict()
	other := &clipsight.Group{
		ID:        "hoge",
		Region:    "ap-northeast-1",
		Namespace: "external",
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
	actual, err := group.Diff(other)
	require.NoError(t, err)
	g.Assert(t, "diff_change", []byte(actual))
	require.True(t, group.Equals(other))
	require.False(t, group.EqualDashboardPermissions(other))
}
