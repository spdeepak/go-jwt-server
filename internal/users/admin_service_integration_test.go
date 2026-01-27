package users

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/internal/db"
	"github.com/spdeepak/go-jwt-server/internal/users/repository"
)

func TestAdminService_LockUserById_NOK(t *testing.T) {
	dbConnection := db.Connect(dbConfig)
	userQuery := repository.New(dbConnection)
	admin_service := NewAdminService(userQuery)
	err := admin_service.LockUserById(context.Background(), uuid.New())
	assert.Error(t, err)
}
