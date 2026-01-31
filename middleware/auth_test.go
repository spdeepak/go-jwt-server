package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthPolicy(t *testing.T) {
	tesPolicy := authPolicy{
		AnyOf: of{
			Roles:       []string{"admin"},
			Permissions: []string{"roles:read"},
		},
	}
	assert.True(t, tesPolicy.evalAnyOf([]string{"admin"}, []string{"roles:read"}, false))
	assert.True(t, tesPolicy.evalAnyOf([]string{"admin"}, []string{"roles:read"}, true))
	assert.True(t, tesPolicy.evalAnyOf([]string{"admin"}, []string{"roles:not-read"}, false))
	assert.True(t, tesPolicy.evalAnyOf([]string{"not-admin"}, []string{"roles:read"}, false))
	tesPolicy.Self = true
	assert.True(t, func() bool {
		return tesPolicy.evalAnyOf([]string{"admin"}, []string{"roles:read"}, true)
	}())
	assert.True(t, func() bool {
		return tesPolicy.evalAnyOf([]string{"admin"}, []string{"roles:read"}, false)
	}())
	assert.True(t, func() bool {
		return tesPolicy.evalAnyOf([]string{"not-admin"}, []string{"roles:not-read"}, true)
	}())
	assert.False(t, func() bool {
		return tesPolicy.evalAnyOf([]string{"not-admin"}, []string{"roles:not-read"}, false)
	}())
	emptyAuthPolicy := authPolicy{}
	assert.True(t, emptyAuthPolicy.evalAnyOf([]string{"not-admin"}, []string{"roles:read"}, false))
}
