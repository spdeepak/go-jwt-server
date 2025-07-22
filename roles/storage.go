package roles

import (
	"context"

	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/roles/repository"
)

type storage struct {
	query repository.Querier
}

type Storage interface {
	CreateNewRole(ctx context.Context, arg repository.CreateNewRoleParams) (repository.Role, error)
	DeleteRoleById(ctx context.Context, id uuid.UUID) error
	GetRoleById(ctx context.Context, id uuid.UUID) (repository.Role, error)
	ListRoles(ctx context.Context) ([]repository.Role, error)
	UpdateRoleById(ctx context.Context, arg repository.UpdateRoleByIdParams) (repository.Role, error)
}

func NewStorage(query repository.Querier) Storage {
	return &storage{
		query: query,
	}
}

func (s *storage) CreateNewRole(ctx context.Context, arg repository.CreateNewRoleParams) (repository.Role, error) {
	return s.query.CreateNewRole(ctx, arg)
}

func (s *storage) DeleteRoleById(ctx context.Context, id uuid.UUID) error {
	return s.query.DeleteRoleById(ctx, id)
}

func (s *storage) GetRoleById(ctx context.Context, id uuid.UUID) (repository.Role, error) {
	return s.query.GetRoleById(ctx, id)
}

func (s *storage) ListRoles(ctx context.Context) ([]repository.Role, error) {
	return s.query.ListRoles(ctx)
}

func (s *storage) UpdateRoleById(ctx context.Context, arg repository.UpdateRoleByIdParams) (repository.Role, error) {
	return s.query.UpdateRoleById(ctx, arg)
}
