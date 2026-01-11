package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSliceSplit(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, SliceSplit("a,b", ","))
	assert.Equal(t, []string{"a", ",", "b"}, SliceSplit("a,b", ""))
}
