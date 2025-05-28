package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens"
	"github.com/spdeepak/go-jwt-server/twoFA"
	"github.com/spdeepak/go-jwt-server/users"
)

type Server struct {
	userService  users.Service
	tokenService tokens.Service
	twoFAService twoFA.Service
}

func NewServer(userService users.Service, tokenService tokens.Service, otpService twoFA.Service) api.ServerInterface {
	return &Server{
		userService:  userService,
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
	if email, present := ctx.Get("X-User-Email"); present {
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
	if email, present := ctx.Get("X-User-Email"); present {
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
	email, emailPresent := ctx.Get("X-User-Email")
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
	response, err := s.userService.Login2FA(ctx, params, userId.(string), verify2FARequest.TwoFACode)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(http.StatusOK, response)
}

func (s *Server) Remove2FA(ctx *gin.Context, params api.Remove2FAParams) {
	_, emailPresent := ctx.Get("X-User-Email")
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
	err := s.twoFAService.Remove2FA(ctx, userId.(string), verify2FARequest.TwoFACode)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
	return
}
