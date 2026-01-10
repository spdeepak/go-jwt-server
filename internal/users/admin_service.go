package users

import (
	"context"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/users/repository"
)

type adminService struct {
	storage repository.Querier
}

type AdminService interface {
	GetListOfUsers(ctx context.Context, params api.GetListOfUsersParams) ([]api.UserDetails, error)
}

func NewAdminService(storage repository.Querier) AdminService {
	return &adminService{
		storage: storage,
	}
}

func (a *adminService) GetListOfUsers(ctx context.Context, params api.GetListOfUsersParams) ([]api.UserDetails, error) {
	return nil, nil
}
