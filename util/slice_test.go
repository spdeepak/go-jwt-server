package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSliceSplit(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, SliceSplit("a,b", ","))
	assert.Equal(t, []string{}, SliceSplit("", ""))
}

func TestHasAny(t *testing.T) {
	assert.True(t, HasAny([]string{"a", "b", "c", "d"}, []string{"d"}))
	assert.False(t, HasAny([]string{"a", "b"}, []string{"c", "d"}))
}

func TestHasAll(t *testing.T) {
	assert.True(t, HasAll([]string{"a", "b"}, []string{"a", "b", "c"}))
	assert.False(t, HasAll([]string{"a", "b"}, []string{"c", "d"}))
}
