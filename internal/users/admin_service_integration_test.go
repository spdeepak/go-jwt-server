package users

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/db"
	"github.com/spdeepak/go-jwt-server/internal/users/repository"
	"github.com/spdeepak/go-jwt-server/util"
)

func TestAdminService_LockUserById_OK(t *testing.T) {
	truncateTables()
	dbConnection := db.Connect(dbConfig)
	userQuery := repository.New(dbConnection)
	admin_service := NewAdminService(userQuery)
	signup_No2fa_OK(t)
	email, err := userQuery.GetUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)
	userId, err := util.PgtypeUUIDToUUID(email.ID)
	assert.NoError(t, err)
	ctx := context.WithValue(context.Background(), "User-ID", userId)
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	users, err := userQuery.GetUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, users)
	assert.False(t, users.Locked)
	lockUser(t, ctx, err, admin_service, users, userQuery)
	dbConnection.Close()
}

func TestAdminService_LockUserById_NOK(t *testing.T) {
	truncateTables()
	dbConnection := db.Connect(dbConfig)
	userQuery := repository.New(dbConnection)
	admin_service := NewAdminService(userQuery)
	signup_No2fa_OK(t)
	email, err := userQuery.GetUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)
	userId, err := util.PgtypeUUIDToUUID(email.ID)
	assert.NoError(t, err)
	ctx := context.WithValue(context.Background(), "User-ID", userId)
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	err = admin_service.LockUserById(ctx, uuid.New(), api.LockUserParams{UserAgent: "service-test"})
	assert.Error(t, err)
	dbConnection.Close()
}

func TestAdminService_UnlockUserById_OK(t *testing.T) {
	truncateTables()
	dbConnection := db.Connect(dbConfig)
	userQuery := repository.New(dbConnection)
	admin_service := NewAdminService(userQuery)
	signup_No2fa_OK(t)
	email, err := userQuery.GetUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)
	userId, err := util.PgtypeUUIDToUUID(email.ID)
	assert.NoError(t, err)
	ctx := context.WithValue(context.Background(), "User-ID", userId)
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	users, err := userQuery.GetUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, users)
	assert.False(t, users.Locked)
	lockUser(t, ctx, err, admin_service, users, userQuery)
	unlockUser(t, err, admin_service, users, userQuery)
	dbConnection.Close()
}

func TestAdminService_UnlockUserById_NOK(t *testing.T) {
	truncateTables()
	dbConnection := db.Connect(dbConfig)
	userQuery := repository.New(dbConnection)
	admin_service := NewAdminService(userQuery)
	ctx := context.WithValue(context.Background(), "User-ID", uuid.New())
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	err := admin_service.UnlockUserById(ctx, uuid.New(), api.UnlockUserParams{UserAgent: "service-test"})
	assert.Error(t, err)
	dbConnection.Close()
}

func lockUser(t *testing.T, ctx context.Context, err error, admin_service AdminService, users repository.User, userQuery *repository.Queries) {
	err = admin_service.LockUserById(ctx, users.ID.Bytes, api.LockUserParams{UserAgent: "service-test"})
	assert.NoError(t, err)
	users, err = userQuery.GetUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, users)
	assert.True(t, users.Locked)
}

func unlockUser(t *testing.T, err error, admin_service AdminService, users repository.User, userQuery *repository.Queries) {
	ctx := context.WithValue(context.Background(), "User-ID", uuid.New())
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	err = admin_service.UnlockUserById(ctx, users.ID.Bytes, api.UnlockUserParams{UserAgent: "service-test"})
	assert.NoError(t, err)
	users, err = userQuery.GetUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, users)
	assert.False(t, users.Locked)
}

func TestAdminService_DisableUserById_OK(t *testing.T) {
	truncateTables()
	dbConnection := db.Connect(dbConfig)
	userQuery := repository.New(dbConnection)
	admin_service := NewAdminService(userQuery)
	signup_No2fa_OK(t)
	email, err := userQuery.GetUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)
	userId, err := util.PgtypeUUIDToUUID(email.ID)
	assert.NoError(t, err)
	ctx := context.WithValue(context.Background(), "User-ID", userId)
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	users, err := userQuery.GetUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, users)
	assert.False(t, users.Disabled)
	disableUser(t, err, admin_service, users, userQuery)
	dbConnection.Close()
}

func TestAdminService_DisableUserById_NOK(t *testing.T) {
	truncateTables()
	dbConnection := db.Connect(dbConfig)
	userQuery := repository.New(dbConnection)
	admin_service := NewAdminService(userQuery)
	ctx := context.WithValue(context.Background(), "User-ID", uuid.New())
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	err := admin_service.DisableUserById(ctx, uuid.New(), api.DisableUserParams{UserAgent: "service-test"})
	assert.Error(t, err)
	dbConnection.Close()
}

func TestAdminService_EnableUserById_OK(t *testing.T) {
	truncateTables()
	dbConnection := db.Connect(dbConfig)
	userQuery := repository.New(dbConnection)
	admin_service := NewAdminService(userQuery)
	signup_No2fa_OK(t)
	email, err := userQuery.GetUserByEmail(context.Background(), "first.last@example.com")
	assert.NoError(t, err)
	userId, err := util.PgtypeUUIDToUUID(email.ID)
	assert.NoError(t, err)
	ctx := context.WithValue(context.Background(), "User-ID", userId)
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	users, err := userQuery.GetUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, users)
	assert.False(t, users.Locked)
	disableUser(t, err, admin_service, users, userQuery)
	enableUser(t, err, admin_service, users, userQuery)
	dbConnection.Close()
}

func TestAdminService_EnableUserById_NOK(t *testing.T) {
	truncateTables()
	dbConnection := db.Connect(dbConfig)
	userQuery := repository.New(dbConnection)
	admin_service := NewAdminService(userQuery)
	ctx := context.WithValue(context.Background(), "User-ID", uuid.New())
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	err := admin_service.EnableUserById(ctx, uuid.New(), api.EnableUserParams{UserAgent: "service-test"})
	assert.Error(t, err)
	dbConnection.Close()
}

func disableUser(t *testing.T, err error, admin_service AdminService, users repository.User, userQuery *repository.Queries) {
	ctx := context.WithValue(context.Background(), "User-ID", uuid.New())
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	err = admin_service.DisableUserById(ctx, users.ID.Bytes, api.DisableUserParams{UserAgent: "service-test"})
	assert.NoError(t, err)
	users, err = userQuery.GetUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, users)
	assert.True(t, users.Disabled)
}

func enableUser(t *testing.T, err error, admin_service AdminService, users repository.User, userQuery *repository.Queries) {
	ctx := context.WithValue(context.Background(), "User-ID", uuid.New())
	ctx = context.WithValue(ctx, "user-ip", "127.0.0.1")
	err = admin_service.EnableUserById(ctx, users.ID.Bytes, api.EnableUserParams{UserAgent: "service-test"})
	assert.NoError(t, err)
	users, err = userQuery.GetUserByEmail(ctx, "first.last@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, users)
	assert.False(t, users.Disabled)
}
