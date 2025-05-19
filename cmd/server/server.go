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

func (s *Server) Signup(c *gin.Context) {
	var signup api.UserSignup
	if err := c.ShouldBindJSON(&signup); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if err := s.userService.Signup(c, signup); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusOK)
}

func (s *Server) Login(c *gin.Context) {
	var login api.UserLogin
	if err := c.ShouldBindJSON(&login); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if response, err := s.userService.Login(c, login); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	} else {
		c.JSON(http.StatusOK, response)
	}
}
