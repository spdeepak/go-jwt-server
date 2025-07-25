package util

import "strings"

func SliceSplit(input, split string) []string {
	if input == "" {
		return []string{}
	}
	return strings.Split(input, split)
}
