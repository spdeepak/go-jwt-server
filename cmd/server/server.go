package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/tokens"
	"github.com/spdeepak/go-jwt-server/twofa"
	"github.com/spdeepak/go-jwt-server/users"
)

type Server struct {
	userService  users.Service
	tokenService tokens.Service
	twoFAService twofa.Service
}

func NewServer(userService users.Service, tokenService tokens.Service, otpService twofa.Service) api.ServerInterface {
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
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if err := s.userService.Signup(ctx, signup); err != nil {
		ctx.Error(err)
		return
	}
	ctx.Status(http.StatusOK)
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
	if email, present := ctx.Get("X-JWT-EMAIL"); present {
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
	if email, present := ctx.Get("X-JWT-EMAIL"); present {
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
	email, emailPresent := ctx.Get("X-JWT-EMAIL")
	userId, userIdPresent := ctx.Get("X-JWT-USER-ID")
	if emailPresent && userIdPresent {
		response, err := s.twoFAService.GenerateSecret(ctx, email.(string), userId.(string))
		if err != nil {
			ctx.Error(err)
			return
		}
		ctx.JSON(http.StatusOK, response)
		return
	}
	ctx.AbortWithStatus(http.StatusUnauthorized)
}

func (s *Server) Verify2FA(ctx *gin.Context, params api.Verify2FAParams) {
}

func (s *Server) Remove2FA(ctx *gin.Context, params api.Remove2FAParams) {
}
