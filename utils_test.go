package clipsight_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/mashiike/clipsight"
	"github.com/stretchr/testify/require"
)

func TestParseIAMRoleARN(t *testing.T) {
	cases := []struct {
		arn      string
		expected *arn.ARN
		errStr   string
	}{
		{
			arn: "arn:aws:iam::0123456789012:role/service-role/Hoge",
			expected: &arn.ARN{
				Partition: "aws",
				Service:   "iam",
				AccountID: "0123456789012",
				Resource:  "role/service-role/Hoge",
			},
		},
		{
			arn:    "arn",
			errStr: "arn: invalid prefix",
		},
		{
			arn:    "arn:aws:quicksight:ap-northeast-1:0123456789012:user/default/Hoge/hoge",
			errStr: "arn service is not IAM",
		},
		{
			arn:    "arn:aws:iam::0123456789012:group/hoge",
			errStr: "arn resource is not IAM Role",
		},
	}

	for _, c := range cases {
		t.Run(c.arn, func(t *testing.T) {
			actual, err := clipsight.ParseIAMRoleARN(c.arn)
			if c.errStr == "" {
				require.NoError(t, err)
				require.EqualValues(t, c.expected, actual)
			} else {
				require.EqualError(t, err, c.errStr)
			}
		})
	}
}
