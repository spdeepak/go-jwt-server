package users

import (
	"context"

	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/users/repository"
	"github.com/spdeepak/go-jwt-server/util"
)

type (
	adminService struct {
		storage repository.Querier
	}
	AdminService interface {
		GetListOfUsers(ctx context.Context, params api.GetListOfUsersParams) ([]api.UserDetails, error)
		LockUserById(ctx context.Context, id uuid.UUID, params api.LockUserParams) error
		UnlockUserById(ctx context.Context, id uuid.UUID, params api.UnlockUserParams) error
		DisableUserById(ctx context.Context, id uuid.UUID, params api.DisableUserParams) error
		EnableUserById(ctx context.Context, id uuid.UUID, params api.EnableUserParams) error
	}
)

func NewAdminService(storage repository.Querier) AdminService {
	return &adminService{
		storage: storage,
	}
}

func (a *adminService) GetListOfUsers(ctx context.Context, params api.GetListOfUsersParams) ([]api.UserDetails, error) {
	return nil, nil
}

func (a *adminService) LockUserById(ctx context.Context, id uuid.UUID, params api.LockUserParams) error {
	userId, err := a.storage.LockUserById(ctx, repository.LockUserByIdParams{
		UserID:    util.UUIDToPgtypeUUID(id),
		ActorID:   util.UUIDToPgtypeUUID(ctx.Value("User-ID").(uuid.UUID)),
		IpAddress: ctx.Value("user-ip").(string),
		UserAgent: params.UserAgent,
	})
	if !userId.Valid || (err != nil && err.Error() == "no rows in result set") {
		return httperror.NewWithMetadata(httperror.UserNotFound, "Invalid user id")
	} else if err != nil {
		return httperror.NewWithMetadata(httperror.UserOperationFailed, "Failed to lock user")
	}
	return nil
}

func (a *adminService) UnlockUserById(ctx context.Context, id uuid.UUID, params api.UnlockUserParams) error {
	userId, err := a.storage.UnlockUserById(ctx, repository.UnlockUserByIdParams{
		UserID:    util.UUIDToPgtypeUUID(id),
		ActorID:   util.UUIDToPgtypeUUID(ctx.Value("User-ID").(uuid.UUID)),
		IpAddress: ctx.Value("user-ip").(string),
		UserAgent: params.UserAgent,
	})
	if !userId.Valid || (err != nil && err.Error() == "no rows in result set") {
		return httperror.NewWithMetadata(httperror.UserNotFound, "Invalid user id")
	} else if err != nil {
		return httperror.NewWithMetadata(httperror.UserOperationFailed, "Failed to unlock user")
	}
	return nil
}

func (a *adminService) DisableUserById(ctx context.Context, id uuid.UUID, params api.DisableUserParams) error {
	userId, err := a.storage.DisableUserById(ctx, repository.DisableUserByIdParams{
		UserID:    util.UUIDToPgtypeUUID(id),
		ActorID:   util.UUIDToPgtypeUUID(ctx.Value("User-ID").(uuid.UUID)),
		IpAddress: ctx.Value("user-ip").(string),
		UserAgent: params.UserAgent,
	})
	if !userId.Valid || (err != nil && err.Error() == "no rows in result set") {
		return httperror.NewWithMetadata(httperror.UserNotFound, "Invalid user id")
	} else if err != nil {
		return httperror.NewWithMetadata(httperror.UserOperationFailed, "Failed to disable user")
	}
	return nil
}

func (a *adminService) EnableUserById(ctx context.Context, id uuid.UUID, params api.EnableUserParams) error {
	userId, err := a.storage.EnableUserById(ctx, repository.EnableUserByIdParams{
		UserID:    util.UUIDToPgtypeUUID(id),
		ActorID:   util.UUIDToPgtypeUUID(ctx.Value("User-ID").(uuid.UUID)),
		IpAddress: ctx.Value("user-ip").(string),
		UserAgent: params.UserAgent,
	})
	if !userId.Valid || (err != nil && err.Error() == "no rows in result set") {
		return httperror.NewWithMetadata(httperror.UserNotFound, "Invalid user id")
	} else if err != nil {
		return httperror.NewWithMetadata(httperror.UserOperationFailed, "Failed to enable user")
	}
	return nil
}
