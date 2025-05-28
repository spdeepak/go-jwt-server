package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPasswordValidator(t *testing.T) {
	assert.True(t, PasswordValidator("DOrrWPfj5!*"))
	assert.True(t, PasswordValidator("Drrfj5!*"))
	assert.False(t, PasswordValidator("Drfj5!*"))
}
