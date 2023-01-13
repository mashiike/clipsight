package clipsight

import (
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

func ParseIAMRoleARN(arnStr string) (*arn.ARN, error) {
	obj, err := arn.Parse(arnStr)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(obj.Service, "IAM") {
		return nil, errors.New("arn service is not IAM")
	}
	if !strings.HasPrefix(obj.Resource, "role/") {
		return nil, errors.New("arn resource is not IAM Role")
	}
	return &obj, err
}

func GetIAMRoleName(arnStr string) (string, error) {
	obj, err := ParseIAMRoleARN(arnStr)
	if err != nil {
		return "", err
	}
	parts := strings.Split(obj.Resource, "/")
	return parts[len(parts)-1], nil
}
