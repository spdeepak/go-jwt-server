package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/tokens"
	"github.com/spdeepak/go-jwt-server/users"
)

type Server struct {
	userService  users.Service
	tokenService tokens.Service
}

func NewServer(userService users.Service, tokenService tokens.Service) api.ServerInterface {
	return &Server{
		userService:  userService,
		tokenService: tokenService,
	}
}

func (s *Server) GetLive(c *gin.Context) {
	c.Status(http.StatusOK)
}

func (s *Server) GetReady(c *gin.Context) {
	c.Status(http.StatusOK)
}

func (s *Server) Signup(c *gin.Context, params api.SignupParams) {
	var signup api.UserSignup
	if err := c.ShouldBindJSON(&signup); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if err := s.userService.Signup(c, signup); err != nil {
		c.Error(err)
		return
	}
	c.Status(http.StatusOK)
}

func (s *Server) Login(c *gin.Context, params api.LoginParams) {
	var login api.UserLogin
	if err := c.ShouldBindJSON(&login); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if response, err := s.userService.Login(c, params, login); err != nil {
		c.Error(err)
		return
	} else {
		c.JSON(http.StatusOK, response)
	}
}

func (s *Server) Refresh(ctx *gin.Context, params api.RefreshParams) {
	if err := s.tokenService.VerifyToken(ctx); err != nil {
		ctx.Error(err)
		return
	}
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
	if err := s.tokenService.VerifyToken(ctx); err != nil {
		ctx.Error(err)
		return
	}
	var revokeRefresh api.RevokeRefresh
	if err := ctx.ShouldBindJSON(&revokeRefresh); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
}
