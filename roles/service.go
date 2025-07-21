package roles

import (
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
	CreateNewRole(ctx *gin.Context, arg api.CreateNewRoleParams, request api.CreateRole) (api.RoleResponse, error)
	DeleteRoleById(ctx *gin.Context, id uuid.UUID) error
	GetRoleById(ctx *gin.Context, id uuid.UUID) (api.RoleResponse, error)
	ListRoles(ctx *gin.Context) ([]api.RoleResponse, error)
	UpdateRoleById(ctx *gin.Context, arg repository.UpdateRoleByIdParams) error
}

func NewService(storage Storage) Service {
	return &service{
		storage: storage,
	}
}

func (s *service) CreateNewRole(ctx *gin.Context, arg api.CreateNewRoleParams, request api.CreateRole) (api.RoleResponse, error) {
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
	//TODO implement me
	panic("implement me")
}

func (s *service) GetRoleById(ctx *gin.Context, id uuid.UUID) (api.RoleResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s *service) ListRoles(ctx *gin.Context) ([]api.RoleResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (s *service) UpdateRoleById(ctx *gin.Context, arg repository.UpdateRoleByIdParams) error {
	//TODO implement me
	panic("implement me")
}
