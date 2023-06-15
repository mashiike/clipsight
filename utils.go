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

type equalable[T any] interface {
	EqualIdentifiers(T) bool
	Equals(T) bool
}

func ListPickup[T equalable[T]](list []T, item T) (T, bool) {
	for _, listItem := range list {
		if listItem.EqualIdentifiers(item) {
			return listItem, true
		}
	}
	return item, false
}

func ListContains[T equalable[T]](list []T, item T) bool {
	_, ok := ListPickup(list, item)
	return ok
}

func ListDiff[T equalable[T]](a []T, b []T) (added []T, changes []T, removed []T) {
	for _, itemA := range a {
		found := false
		for _, itemB := range b {
			if itemB.EqualIdentifiers(itemA) {
				found = true
				if !itemB.Equals(itemA) {
					changes = append(changes, itemB)
				}
				break
			}
		}
		if !found {
			removed = append(removed, itemA)
		}
	}
	for _, itemB := range b {
		found := false
		for _, itemA := range a {
			if itemB.EqualIdentifiers(itemA) {
				found = true
				break
			}
		}
		if !found {
			added = append(added, itemB)
		}
	}
	return
}
