package util

import "strings"

func SliceSplit(input, split string) []string {
	return strings.Split(input, split)
}
