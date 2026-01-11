package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/permissions"
	"github.com/spdeepak/go-jwt-server/internal/roles"
	"github.com/spdeepak/go-jwt-server/internal/tokens"
	"github.com/spdeepak/go-jwt-server/internal/twoFA"
	"github.com/spdeepak/go-jwt-server/internal/users"
	"github.com/spdeepak/go-jwt-server/util"
)

const emailHeader = "User-Email"

type Server struct {
	userService       users.Service
	roleService       roles.Service
	permissionService permissions.Service
	tokenService      tokens.Service
	twoFAService      twoFA.Service
}

func NewServer(userService users.Service, roleService roles.Service, permissionService permissions.Service, tokenService tokens.Service, otpService twoFA.Service) api.ServerInterface {
	return &Server{
		userService:       userService,
		roleService:       roleService,
		permissionService: permissionService,
		tokenService:      tokenService,
		twoFAService:      otpService,
	}
}

func (s *Server) GetLive(ctx *gin.Context) {
	ctx.Status(http.StatusOK)
}

func (s *Server) GetReady(ctx *gin.Context) {
	ctx.Status(http.StatusOK)
}

func (s *Server) Signup(ctx *gin.Context, params api.SignupParams) {
	var signup api.UserSignup
	if err := ctx.ShouldBindJSON(&signup); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	if !util.PasswordValidator(signup.Password) {
		ctx.AbortWithError(http.StatusBadRequest, httperror.NewWithDescription("Password doesn't meet requirements", http.StatusBadRequest))
		return
	}
	if res, err := s.userService.Signup(ctx, signup); err != nil {
		ctx.AbortWithError(err.(httperror.HttpError).StatusCode, err)
		return
	} else if res.QrImage != "" || res.Secret != "" {
		ctx.JSON(http.StatusCreated, res)
		return
	}
	ctx.Status(http.StatusCreated)
}

func (s *Server) ChangePassword(ctx *gin.Context, params api.ChangePasswordParams) {

}

func (s *Server) Login(ctx *gin.Context, params api.LoginParams) {
	var login api.UserLogin
	if err := ctx.ShouldBindJSON(&login); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}

	if response, err := s.userService.Login(ctx, params, login); err != nil {
		ctx.Error(err)
		return
	} else {
		ctx.JSON(http.StatusOK, response)
		return
	}
}

func (s *Server) Refresh(ctx *gin.Context, params api.RefreshParams) {
	var refresh api.Refresh
	if err := ctx.ShouldBindJSON(&refresh); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	response, err := s.userService.RefreshToken(ctx, params, refresh)
	if err != nil {
		ctx.Error(err)
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	ctx.JSON(http.StatusOK, response)
}

func (s *Server) RevokeRefreshToken(ctx *gin.Context, params api.RevokeRefreshTokenParams) {
	var revokeRefresh api.RevokeCurrentSession
	if err := ctx.ShouldBindJSON(&revokeRefresh); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	if err := s.tokenService.RevokeRefreshToken(ctx, params, revokeRefresh); err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
	return
}

func (s *Server) RevokeAllTokens(ctx *gin.Context, params api.RevokeAllTokensParams) {
	if email, present := ctx.Get(emailHeader); present {
		err := s.tokenService.RevokeAllTokens(ctx, email.(string))
		if err != nil {
			ctx.Error(err)
			return
		}
		ctx.Status(http.StatusOK)
		return
	}
	ctx.AbortWithStatus(http.StatusUnauthorized)
}

func (s *Server) GetAllSessions(ctx *gin.Context, params api.GetAllSessionsParams) {
	if email, present := ctx.Get(emailHeader); present {
		response, err := s.tokenService.ListActiveSessions(ctx, email.(string))
		if err != nil {
			ctx.Error(err)
			return
		}
		ctx.JSON(http.StatusOK, response)
		return
	}
	ctx.AbortWithStatus(http.StatusUnauthorized)
}

func (s *Server) Create2FA(ctx *gin.Context, params api.Create2FAParams) {
	email, emailPresent := ctx.Get(emailHeader)
	if emailPresent {
		response, err := s.twoFAService.Setup2FA(ctx, email.(string))
		if err != nil {
			ctx.Error(err)
			return
		}
		ctx.JSON(http.StatusCreated, response)
		return
	}
	ctx.AbortWithStatus(http.StatusUnauthorized)
}

func (s *Server) Login2FA(ctx *gin.Context, params api.Login2FAParams) {
	userId, userIdPresent := ctx.Get("User-ID")
	if !userIdPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var verify2FARequest api.Login2FARequest
	if err := ctx.ShouldBindJSON(&verify2FARequest); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	response, err := s.userService.Login2FA(ctx, params, userId.(uuid.UUID), verify2FARequest.TwoFACode)
	if err != nil {
		ctx.Error(err)
		ctx.AbortWithStatus(err.(httperror.HttpError).StatusCode)
		return
	}
	ctx.JSON(http.StatusOK, response)
}

func (s *Server) Remove2FA(ctx *gin.Context, params api.Remove2FAParams) {
	_, emailPresent := ctx.Get(emailHeader)
	userId, userIdPresent := ctx.Get("User-ID")
	if !emailPresent || !userIdPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var verify2FARequest api.Remove2FARequest
	if err := ctx.ShouldBindJSON(&verify2FARequest); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	err := s.twoFAService.Remove2FA(ctx, util.UUIDToPgtypeUUID(userId.(uuid.UUID)), verify2FARequest.TwoFACode)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
	return
}

func (s *Server) CreateNewRole(ctx *gin.Context, params api.CreateNewRoleParams) {
	email, emailPresent := ctx.Get(emailHeader)
	if !emailPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var createRole api.CreateRole
	if err := ctx.ShouldBindJSON(&createRole); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	createNewRole, err := s.roleService.CreateNewRole(ctx, params, email.(string), createRole)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusCreated, createNewRole)
	return
}

func (s *Server) GetRoleById(ctx *gin.Context, id api.UuId, params api.GetRoleByIdParams) {
	roleById, err := s.roleService.GetRoleById(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, roleById)
	return
}

func (s *Server) ListAllRoles(ctx *gin.Context, params api.ListAllRolesParams) {
	listRoles, err := s.roleService.ListRoles(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, listRoles)
	return
}

func (s *Server) UpdateRoleById(ctx *gin.Context, id api.UuId, params api.UpdateRoleByIdParams) {
	email := ctx.GetString(emailHeader)
	if email == "" {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var req api.UpdateRole
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	updatedRole, err := s.roleService.UpdateRoleById(ctx, id, email, params, req)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, updatedRole)
	return
}

func (s *Server) DeleteRoleById(ctx *gin.Context, id api.UuId, params api.DeleteRoleByIdParams) {
	err := s.roleService.DeleteRoleById(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
	return
}

func (s *Server) CreateNewPermission(ctx *gin.Context, params api.CreateNewPermissionParams) {
	_, emailPresent := ctx.Get(emailHeader)
	if !emailPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var createPermission api.CreatePermission
	if err := ctx.ShouldBindJSON(&createPermission); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	createNewPermission, err := s.permissionService.CreateNewPermission(ctx, params, createPermission)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusCreated, createNewPermission)
	return
}

func (s *Server) GetPermissionById(ctx *gin.Context, id api.UuId, params api.GetPermissionByIdParams) {
	permissionById, err := s.permissionService.GetPermissionById(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, permissionById)
	return
}

func (s *Server) ListAllPermissions(ctx *gin.Context, params api.ListAllPermissionsParams) {
	permissionList, err := s.permissionService.ListPermissions(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, permissionList)
	return
}

func (s *Server) UpdatePermissionById(ctx *gin.Context, id api.UuId, params api.UpdatePermissionByIdParams) {
	_, emailPresent := ctx.Get(emailHeader)
	if !emailPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var req api.UpdatePermission
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	updatedPermission, err := s.permissionService.UpdatePermissionById(ctx, id, params, req)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, updatedPermission)
	return
}

func (s *Server) DeletePermissionById(ctx *gin.Context, id api.UuId, params api.DeletePermissionByIdParams) {
	err := s.permissionService.DeletePermissionById(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
	return
}

func (s *Server) AssignPermissionToRole(ctx *gin.Context, id api.UuId, params api.AssignPermissionToRoleParams) {
	email, emailPresent := ctx.Get(emailHeader)
	if !emailPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var req api.AssignPermission
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	if err := s.roleService.AssignPermissionToRole(ctx, id, params, req, email.(string)); err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
	return
}

func (s *Server) UnassignPermissionFromRole(ctx *gin.Context, roleId api.RoleId, permissionId api.PermissionId) {
	if err := s.roleService.UnassignPermissionFromRole(ctx, roleId, permissionId); err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
	return
}

func (s *Server) RolesAndPermissions(ctx *gin.Context, params api.RolesAndPermissionsParams) {
	if rolesAndPermissionLists, err := s.roleService.ListRolesAndItsPermissions(ctx); err != nil {
		ctx.Error(err)
		return
	} else {
		ctx.JSON(http.StatusOK, rolesAndPermissionLists)
		return
	}
}

func (s *Server) GetRolesOfUser(ctx *gin.Context, id api.UuId, params api.GetRolesOfUserParams) {
	if userRolesAndPermissions, err := s.userService.GetUserRolesAndPermissions(ctx, id, params); err != nil {
		ctx.Error(err)
		return
	} else {
		ctx.JSON(http.StatusOK, userRolesAndPermissions)
		return
	}
}

func (s *Server) AssignRolesToUser(ctx *gin.Context, id api.UuId, params api.AssignRolesToUserParams) {
	email, emailPresent := ctx.Get(emailHeader)
	if !emailPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var req api.AssignRoleToUser
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.Error(httperror.New(httperror.InvalidRequestBody))
		return
	}
	if err := s.userService.AssignRolesToUser(ctx, id, params, req, email.(string)); err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
	return
}

func (s *Server) RemoveRolesForUser(ctx *gin.Context, userId api.UuId, roleId api.RoleId, params api.RemoveRolesForUserParams) {
	if err := s.userService.UnassignRolesOfUser(ctx, userId, roleId, params); err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
	return
}
