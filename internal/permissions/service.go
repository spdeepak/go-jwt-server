package permissions

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/permissions/repository"
	"github.com/spdeepak/go-jwt-server/util"
)

const emailHeader = "X-User-Email"

type service struct {
	storage repository.Querier
}

type Service interface {
	CreateNewPermission(ctx *gin.Context, params api.CreateNewPermissionParams, request api.CreatePermission) (api.PermissionResponse, error)
	DeletePermissionById(ctx *gin.Context, id uuid.UUID) error
	GetPermissionById(ctx *gin.Context, id uuid.UUID) (api.PermissionResponse, error)
	ListPermissions(ctx *gin.Context) ([]api.PermissionResponse, error)
	UpdatePermissionById(ctx *gin.Context, id api.UuId, params api.UpdatePermissionByIdParams, req api.UpdatePermission) (api.PermissionResponse, error)
}

func NewService(storage repository.Querier) Service {
	return &service{
		storage: storage,
	}
}

func (s *service) CreateNewPermission(ctx *gin.Context, params api.CreateNewPermissionParams, request api.CreatePermission) (api.PermissionResponse, error) {
	email, _ := ctx.Get(emailHeader)
	createNewPermission := repository.CreateNewPermissionParams{
		Name:        request.Name,
		Description: request.Description,
		CreatedBy:   email.(string),
	}
	createdNewPermission, err := s.storage.CreateNewPermission(ctx, createNewPermission)
	if err != nil {
		if err.Error() == "ERROR: duplicate key value violates unique constraint \"permissions_name_key\" (SQLSTATE 23505)" {
			return api.PermissionResponse{}, httperror.New(httperror.PermissionAlreadyExists)
		}
		return api.PermissionResponse{}, httperror.NewWithMetadata(httperror.PermissionCreationFailed, err.Error())
	}
	id, _ := util.PgtypeUUIDToUUID(createdNewPermission.ID)
	return api.PermissionResponse{
		CreatedAt:   createdNewPermission.CreatedAt,
		CreatedBy:   createdNewPermission.CreatedBy,
		Description: createdNewPermission.Description,
		Id:          id,
		Name:        createdNewPermission.Name,
		UpdatedAt:   createdNewPermission.UpdatedAt,
		UpdatedBy:   createdNewPermission.UpdatedBy,
	}, nil
}

func (s *service) DeletePermissionById(ctx *gin.Context, id uuid.UUID) error {
	return s.storage.DeletePermissionById(ctx, util.UUIDToPgtypeUUID(id))
}

func (s *service) GetPermissionById(ctx *gin.Context, id uuid.UUID) (api.PermissionResponse, error) {
	getPermissionById, err := s.storage.GetPermissionById(ctx, util.UUIDToPgtypeUUID(id))
	if err != nil {
		if err.Error() == "no rows in result set" {
			return api.PermissionResponse{}, httperror.New(httperror.PermissionDoesntExist)
		}
		return api.PermissionResponse{}, httperror.NewWithDescription("Couldn't fetch Permission for given ID", http.StatusInternalServerError)
	}
	return api.PermissionResponse{
		CreatedAt:   getPermissionById.CreatedAt,
		CreatedBy:   getPermissionById.CreatedBy,
		Description: getPermissionById.Description,
		Name:        getPermissionById.Name,
		UpdatedAt:   getPermissionById.UpdatedAt,
		UpdatedBy:   getPermissionById.UpdatedBy,
	}, nil
}

func (s *service) ListPermissions(ctx *gin.Context) ([]api.PermissionResponse, error) {
	listPermissions, err := s.storage.ListPermissions(ctx)
	if err != nil {
		return nil, err
	}
	permissions := make([]api.PermissionResponse, len(listPermissions))
	for index, permission := range listPermissions {
		id, _ := util.PgtypeUUIDToUUID(permission.ID)
		permissions[index] = api.PermissionResponse{
			CreatedAt:   permission.CreatedAt,
			CreatedBy:   permission.CreatedBy,
			Description: permission.Description,
			Id:          id,
			Name:        permission.Name,
			UpdatedAt:   permission.UpdatedAt,
			UpdatedBy:   permission.UpdatedBy,
		}
	}
	return permissions, nil
}

func (s *service) UpdatePermissionById(ctx *gin.Context, id api.UuId, params api.UpdatePermissionByIdParams, req api.UpdatePermission) (api.PermissionResponse, error) {
	email, _ := ctx.Get(emailHeader)
	updatePermissionById := repository.UpdatePermissionByIdParams{
		ID:        util.UUIDToPgtypeUUID(id),
		UpdatedBy: email.(string),
	}
	if req.Description != nil && *req.Description != "" {
		updatePermissionById.Description = pgtype.Text{
			String: *req.Description,
			Valid:  true,
		}
	}
	if req.Name != nil && *req.Name != "" {
		updatePermissionById.Name = pgtype.Text{
			String: *req.Name,
			Valid:  true,
		}
	}
	updatedPermission, err := s.storage.UpdatePermissionById(ctx, updatePermissionById)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return api.PermissionResponse{}, httperror.New(httperror.PermissionDoesntExist)
		}
		return api.PermissionResponse{}, httperror.NewWithDescription("Couldn't fetch Permission for given ID", http.StatusInternalServerError)
	}
	return api.PermissionResponse{
		CreatedAt:   updatedPermission.CreatedAt,
		CreatedBy:   updatedPermission.CreatedBy,
		Description: updatedPermission.Description,
		Name:        updatedPermission.Name,
		UpdatedAt:   updatedPermission.UpdatedAt,
		UpdatedBy:   updatedPermission.UpdatedBy,
	}, nil
}
