package roles

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/roles/repository"
)

const emailHeader = "X-User-Email"

type service struct {
	storage Storage
}

type Service interface {
	CreateNewRole(ctx *gin.Context, params api.CreateNewRoleParams, request api.CreateRole) (api.RoleResponse, error)
	DeleteRoleById(ctx *gin.Context, id uuid.UUID) error
	GetRoleById(ctx *gin.Context, id uuid.UUID) (api.RoleResponse, error)
	ListRoles(ctx *gin.Context) ([]api.RoleResponse, error)
	UpdateRoleById(ctx *gin.Context, id api.UuId, params api.UpdateRoleByIdParams, req api.UpdateRole) (api.RoleResponse, error)
}

func NewService(storage Storage) Service {
	return &service{
		storage: storage,
	}
}

func (s *service) CreateNewRole(ctx *gin.Context, params api.CreateNewRoleParams, request api.CreateRole) (api.RoleResponse, error) {
	email, _ := ctx.Get(emailHeader)
	createNewRole := repository.CreateNewRoleParams{
		Name:        request.Name,
		Description: request.Description,
		CreatedBy:   email.(string),
	}
	createdNewRole, err := s.storage.CreateNewRole(ctx, createNewRole)
	if err != nil {
		return api.RoleResponse{}, err
	}
	return api.RoleResponse{
		CreatedAt:   createdNewRole.CreatedAt,
		CreatedBy:   createdNewRole.CreatedBy,
		Description: createdNewRole.Description,
		Name:        createdNewRole.Name,
		UpdatedAt:   createdNewRole.UpdatedAt,
		UpdatedBy:   createdNewRole.UpdatedBy,
	}, nil
}

func (s *service) DeleteRoleById(ctx *gin.Context, id uuid.UUID) error {
	return s.storage.DeleteRoleById(ctx, id)
}

func (s *service) GetRoleById(ctx *gin.Context, id uuid.UUID) (api.RoleResponse, error) {
	getRoleById, err := s.storage.GetRoleById(ctx, id)
	if err != nil {
		return api.RoleResponse{}, err
	}
	return api.RoleResponse{
		CreatedAt:   getRoleById.CreatedAt,
		CreatedBy:   getRoleById.CreatedBy,
		Description: getRoleById.Description,
		Name:        getRoleById.Name,
		UpdatedAt:   getRoleById.UpdatedAt,
		UpdatedBy:   getRoleById.UpdatedBy,
	}, nil
}

func (s *service) ListRoles(ctx *gin.Context) ([]api.RoleResponse, error) {
	listRoles, err := s.storage.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	roles := make([]api.RoleResponse, len(listRoles))
	for index, role := range listRoles {
		roles[index] = api.RoleResponse{
			CreatedAt:   role.CreatedAt,
			CreatedBy:   role.CreatedBy,
			Description: role.Description,
			Name:        role.Name,
			UpdatedAt:   role.UpdatedAt,
			UpdatedBy:   role.UpdatedBy,
		}
	}
	return roles, nil
}

func (s *service) UpdateRoleById(ctx *gin.Context, id api.UuId, params api.UpdateRoleByIdParams, req api.UpdateRole) (api.RoleResponse, error) {
	email, _ := ctx.Get(emailHeader)
	updateRoleById := repository.UpdateRoleByIdParams{
		ID:        id,
		UpdatedBy: email.(string),
	}
	if req.Description != nil && *req.Description != "" {
		updateRoleById.Description = sql.NullString{
			String: *req.Description,
			Valid:  true,
		}
	}
	if req.Name != nil && *req.Name != "" {
		updateRoleById.Name = sql.NullString{
			String: *req.Name,
			Valid:  true,
		}
	}
	updatedRole, err := s.storage.UpdateRoleById(ctx, updateRoleById)
	if err != nil {
		return api.RoleResponse{}, err
	}
	return api.RoleResponse{
		CreatedAt:   updatedRole.CreatedAt,
		CreatedBy:   updatedRole.CreatedBy,
		Description: updatedRole.Description,
		Name:        updatedRole.Name,
		UpdatedAt:   updatedRole.UpdatedAt,
		UpdatedBy:   updatedRole.UpdatedBy,
	}, nil
}
