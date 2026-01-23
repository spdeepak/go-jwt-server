package util

import "strings"

func SliceSplit(input, split string) []string {
	if input == "" {
		return []string{}
	}
	return strings.Split(input, split)
}

// HasAny returns true if any element of b is present in a. It uses two pointer intersection algorithm.
func HasAny(mainList, subList []string) bool {
	i, j := 0, 0
	for i < len(mainList) && j < len(subList) {
		switch {
		case mainList[i] == subList[j]:
			return true
		case mainList[i] < subList[j]:
			i++
		default:
			j++
		}
	}
	return false
}

func HasAll(mainList, checkList []string) bool {
	i, j := 0, 0
	for i < len(mainList) && j < len(checkList) {
		if mainList[i] == checkList[j] {
			i++
		}
		j++
	}
	return i == len(mainList)
}
