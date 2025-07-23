package permissions

import (
	"context"

	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/permissions/repository"
)

type storage struct {
	query repository.Querier
}

type Storage interface {
	CreateNewPermission(ctx context.Context, arg repository.CreateNewPermissionParams) (repository.Permission, error)
	DeletePermissionById(ctx context.Context, id uuid.UUID) error
	GetPermissionById(ctx context.Context, id uuid.UUID) (repository.Permission, error)
	ListPermissions(ctx context.Context) ([]repository.Permission, error)
	UpdatePermissionById(ctx context.Context, arg repository.UpdatePermissionByIdParams) (repository.Permission, error)
}

func NewStorage(query repository.Querier) Storage {
	return &storage{
		query: query,
	}
}

func (s *storage) CreateNewPermission(ctx context.Context, arg repository.CreateNewPermissionParams) (repository.Permission, error) {
	return s.query.CreateNewPermission(ctx, arg)
}

func (s *storage) DeletePermissionById(ctx context.Context, id uuid.UUID) error {
	return s.query.DeletePermissionById(ctx, id)
}

func (s *storage) GetPermissionById(ctx context.Context, id uuid.UUID) (repository.Permission, error) {
	return s.query.GetPermissionById(ctx, id)
}

func (s *storage) ListPermissions(ctx context.Context) ([]repository.Permission, error) {
	return s.query.ListPermissions(ctx)
}

func (s *storage) UpdatePermissionById(ctx context.Context, arg repository.UpdatePermissionByIdParams) (repository.Permission, error) {
	return s.query.UpdatePermissionById(ctx, arg)
}
