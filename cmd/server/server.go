package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/permissions"
	"github.com/spdeepak/go-jwt-server/roles"
	"github.com/spdeepak/go-jwt-server/tokens"
	"github.com/spdeepak/go-jwt-server/twoFA"
	"github.com/spdeepak/go-jwt-server/users"
	"github.com/spdeepak/go-jwt-server/util"
)

const emailHeader = "X-User-Email"

type Server struct {
	userService       users.Service
	roleService       roles.Service
	permissionService permissions.Service
	tokenService      tokens.Service
	twoFAService      twoFA.Service
}

func NewServer(userService users.Service, roleService roles.Service, tokenService tokens.Service, otpService twoFA.Service) api.ServerInterface {
	return &Server{
		userService:  userService,
		roleService:  roleService,
		tokenService: tokenService,
		twoFAService: otpService,
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
		ctx.AbortWithError(http.StatusBadRequest, httperror.NewWithDescription(err.Error(), http.StatusBadRequest))
		return
	}
	if !util.PasswordValidator(signup.Password) {
		ctx.AbortWithError(http.StatusBadRequest, httperror.NewWithDescription("Password doesn't meet requirements", http.StatusBadRequest))
		return
	}
	if res, err := s.userService.Signup(ctx, signup); err != nil {
		ctx.AbortWithError(http.StatusInternalServerError, err)
		return
	} else if res.QrImage != "" || res.Secret != "" {
		ctx.JSON(http.StatusCreated, res)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func (s *Server) ChangePassword(ctx *gin.Context, params api.ChangePasswordParams) {

}

func (s *Server) Login(ctx *gin.Context, params api.LoginParams) {
	var login api.UserLogin
	if err := ctx.ShouldBindJSON(&login); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if response, err := s.userService.Login(ctx, params, login); err != nil {
		ctx.Error(err)
		return
	} else {
		ctx.JSON(http.StatusOK, response)
	}
}

func (s *Server) Refresh(ctx *gin.Context, params api.RefreshParams) {
	var refresh api.Refresh
	if err := ctx.ShouldBindJSON(&refresh); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		ctx.Error(err)
		return
	}

	if response, err := s.userService.RefreshToken(ctx, params, refresh); err != nil {
		ctx.Error(err)
		return
	} else {
		ctx.JSON(http.StatusOK, response)
	}
}

func (s *Server) RevokeRefreshToken(ctx *gin.Context, params api.RevokeRefreshTokenParams) {
	var revokeRefresh api.RevokeCurrentSession
	if err := ctx.ShouldBindJSON(&revokeRefresh); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if err := s.tokenService.RevokeRefreshToken(ctx, params, revokeRefresh); err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
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
	userId, userIdPresent := ctx.Get("X-User-ID")
	if !userIdPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var verify2FARequest api.Login2FARequest
	if err := ctx.ShouldBindJSON(&verify2FARequest); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	response, err := s.userService.Login2FA(ctx, params, userId.(uuid.UUID), verify2FARequest.TwoFACode)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, response)
}

func (s *Server) Remove2FA(ctx *gin.Context, params api.Remove2FAParams) {
	_, emailPresent := ctx.Get(emailHeader)
	userId, userIdPresent := ctx.Get("X-User-ID")
	if !emailPresent || !userIdPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var verify2FARequest api.Remove2FARequest
	if err := ctx.ShouldBindJSON(&verify2FARequest); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	err := s.twoFAService.Remove2FA(ctx, userId.(uuid.UUID), verify2FARequest.TwoFACode)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
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

func (s *Server) CreateNewPermission(ctx *gin.Context, params api.CreateNewPermissionParams) {
	_, emailPresent := ctx.Get(emailHeader)
	if !emailPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var createPermission api.CreatePermission
	if err := ctx.ShouldBindJSON(&createPermission); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
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

func (s *Server) DeletePermissionById(ctx *gin.Context, id api.UuId, params api.DeletePermissionByIdParams) {
	err := s.permissionService.DeletePermissionById(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
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

func (s *Server) UpdatePermissionById(ctx *gin.Context, id api.UuId, params api.UpdatePermissionByIdParams) {
	_, emailPresent := ctx.Get(emailHeader)
	if !emailPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var req api.UpdatePermission
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.Status(http.StatusBadRequest)
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

func (s *Server) ListAllRoles(ctx *gin.Context, params api.ListAllRolesParams) {
	listRoles, err := s.roleService.ListRoles(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, listRoles)
	return
}

func (s *Server) CreateNewRole(ctx *gin.Context, params api.CreateNewRoleParams) {
	_, emailPresent := ctx.Get(emailHeader)
	if !emailPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var createRole api.CreateRole
	if err := ctx.ShouldBindJSON(&createRole); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	createNewRole, err := s.roleService.CreateNewRole(ctx, params, createRole)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusCreated, createNewRole)
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

func (s *Server) GetRoleById(ctx *gin.Context, id api.UuId, params api.GetRoleByIdParams) {
	roleById, err := s.roleService.GetRoleById(ctx, id)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, roleById)
	return
}

func (s *Server) UpdateRoleById(ctx *gin.Context, id api.UuId, params api.UpdateRoleByIdParams) {
	_, emailPresent := ctx.Get(emailHeader)
	if !emailPresent {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	var req api.UpdateRole
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.Status(http.StatusBadRequest)
		return
	}
	updatedRole, err := s.roleService.UpdateRoleById(ctx, id, params, req)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, updatedRole)
	return
}

func (s *Server) AssignPermissionToRole(ctx *gin.Context, id api.UuId, params api.AssignPermissionToRoleParams) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) RemovePermissionFromRole(ctx *gin.Context, roleId api.RoleId, permissionId api.PermissionId) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) GetRolesOfUser(ctx *gin.Context, id api.UuId, params api.GetRolesOfUserParams) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) AssignRolesToUser(ctx *gin.Context, id api.UuId, params api.AssignRolesToUserParams) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) RemoveRolesForUser(ctx *gin.Context, id api.UuId, roleId api.RoleId, params api.RemoveRolesForUserParams) {
	//TODO implement me
	panic("implement me")
}
