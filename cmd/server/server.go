package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/users"
)

type Server struct {
	userService users.Service
}

func NewServer(userService users.Service) api.ServerInterface {
	return &Server{
		userService: userService,
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

func (s *Server) Refresh(c *gin.Context, params api.RefreshParams) {
	var refresh api.Refresh
	if err := c.ShouldBindJSON(&refresh); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if response, err := s.userService.RefreshToken(c, params, refresh); err != nil {
		c.Error(err)
		return
	} else {
		c.JSON(http.StatusOK, response)
	}
}

func (s *Server) RevokeRefreshToken(c *gin.Context, params api.RevokeRefreshTokenParams) {
	var revokeRefresh api.RevokeRefresh
	if err := c.ShouldBindJSON(&revokeRefresh); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
}
