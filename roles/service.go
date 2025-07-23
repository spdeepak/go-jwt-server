package roles

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
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
	AssignPermissionToRole(ctx *gin.Context, roleId api.UuId, params api.AssignPermissionToRoleParams, assignPermission api.AssignPermission, email string) error
	UnassignPermissionFromRole(ctx *gin.Context, roleId api.RoleId, permissionId api.PermissionId) error
	ListRolesAndItsPermissions(ctx context.Context) ([]api.RolesAndPermissionResponse, error)
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
		if err.Error() == "ERROR: duplicate key value violates unique constraint \"roles_name_key\" (SQLSTATE 23505)" {
			return api.RoleResponse{}, httperror.New(httperror.RoleAlreadyExists)
		}
		return api.RoleResponse{}, httperror.NewWithMetadata(httperror.RoleCreationFailed, err.Error())
	}
	return api.RoleResponse{
		CreatedAt:   createdNewRole.CreatedAt,
		CreatedBy:   createdNewRole.CreatedBy,
		Description: createdNewRole.Description,
		Id:          createdNewRole.ID,
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
		if err.Error() == "sql: no rows in result set" {
			return api.RoleResponse{}, httperror.New(httperror.RoleDoesntExist)
		}
		return api.RoleResponse{}, httperror.NewWithDescription("Couldn't fetch Role for given ID", http.StatusInternalServerError)
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
		if err.Error() == "sql: no rows in result set" {
			return api.RoleResponse{}, httperror.New(httperror.RoleDoesntExist)
		}
		return api.RoleResponse{}, httperror.NewWithDescription("Couldn't fetch Role for given ID", http.StatusInternalServerError)
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

func (s *service) AssignPermissionToRole(ctx *gin.Context, roleId api.UuId, params api.AssignPermissionToRoleParams, assignPermission api.AssignPermission, email string) error {
	assignPermissionsToRole := repository.AssignPermissionsParams{
		RoleID:       roleId,
		PermissionID: assignPermission.Ids,
		CreatedBy:    email,
	}
	if err := s.storage.AssignPermissions(ctx, assignPermissionsToRole); err != nil {
		return httperror.NewWithDescription("Failed to assign permission to role", http.StatusInternalServerError)
	}
	return nil
}

func (s *service) UnassignPermissionFromRole(ctx *gin.Context, roleId api.RoleId, permissionId api.PermissionId) error {
	UnassignPermissionFromRole := repository.UnAssignPermissionParams{
		RoleID:       roleId,
		PermissionID: permissionId,
	}
	if err := s.storage.UnassignPermissions(ctx, UnassignPermissionFromRole); err != nil {
		return httperror.NewWithDescription("Failed to assign permission to role", http.StatusInternalServerError)
	}
	return nil
}

func (s *service) ListRolesAndItsPermissions(ctx context.Context) ([]api.RolesAndPermissionResponse, error) {
	rolesAndItsPermissions, err := s.storage.ListRolesAndItsPermissions(ctx)
	if err != nil {
		return nil, err
	}

	roleIdRolePermissionMap := make(map[uuid.UUID]*api.RolesAndPermissionResponse)

	for _, rolePermission := range rolesAndItsPermissions {
		rolePermissionResponse, exists := roleIdRolePermissionMap[rolePermission.RoleID]
		if !exists {
			var rolePerm api.RolesAndPermissionResponse
			rolePerm.Roles.CreatedAt = rolePermission.RoleCreatedAt
			rolePerm.Roles.CreatedBy = rolePermission.RoleCreatedBy
			rolePerm.Roles.Description = rolePermission.RoleDescription
			rolePerm.Roles.Id = rolePermission.RoleID
			rolePerm.Roles.Name = rolePermission.RoleName
			rolePerm.Roles.UpdatedAt = rolePermission.RoleUpdatedAt
			rolePerm.Roles.UpdatedBy = rolePermission.RoleUpdatedBy
			roleIdRolePermissionMap[rolePermission.RoleID] = &rolePerm
			rolePermissionResponse = roleIdRolePermissionMap[rolePermission.RoleID]
		}

		if rolePermission.PermissionID.Valid {
			rolePermissionResponse.Roles.Permissions = append(rolePermissionResponse.Roles.Permissions, api.PermissionResponse{
				CreatedAt:   rolePermission.PermissionCreatedAt.Time,
				CreatedBy:   rolePermission.PermissionCreatedBy.String,
				Description: rolePermission.PermissionDescription.String,
				Id:          rolePermission.PermissionID.UUID,
				Name:        rolePermission.PermissionName.String,
				UpdatedAt:   rolePermission.PermissionUpdatedAt.Time,
				UpdatedBy:   rolePermission.PermissionUpdatedBy.String,
			})
		}
	}

	rolePermissionResponse := make([]api.RolesAndPermissionResponse, len(roleIdRolePermissionMap))
	for _, role := range roleIdRolePermissionMap {
		rolePermissionResponse = append(rolePermissionResponse, *role)
	}

	return rolePermissionResponse, nil
}
