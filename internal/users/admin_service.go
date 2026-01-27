package users

import (
	"context"

	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/users/repository"
	"github.com/spdeepak/go-jwt-server/util"
)

type (
	adminService struct {
		storage repository.Querier
	}
	AdminService interface {
		GetListOfUsers(ctx context.Context, params api.GetListOfUsersParams) ([]api.UserDetails, error)
		LockUserById(ctx context.Context, id uuid.UUID) error
		UnlockUserById(ctx context.Context, id uuid.UUID) error
		DisableUserById(ctx context.Context, id uuid.UUID) error
		EnableUserById(ctx context.Context, id uuid.UUID) error
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

func (a *adminService) LockUserById(ctx context.Context, id uuid.UUID) error {
	err := a.storage.LockUserById(ctx, util.UUIDToPgtypeUUID(id))
	if err != nil {
		return err
	}
	return nil
}

func (a *adminService) UnlockUserById(ctx context.Context, id uuid.UUID) error {
	err := a.storage.UnlockUserById(ctx, util.UUIDToPgtypeUUID(id))
	if err != nil {
		return err
	}
	return nil
}

func (a *adminService) DisableUserById(ctx context.Context, id uuid.UUID) error {
	err := a.storage.DisableUserById(ctx, util.UUIDToPgtypeUUID(id))
	if err != nil {
		return err
	}
	return nil
}

func (a *adminService) EnableUserById(ctx context.Context, id uuid.UUID) error {
	err := a.storage.EnableUserById(ctx, util.UUIDToPgtypeUUID(id))
	if err != nil {
		return err
	}
	return nil
}
