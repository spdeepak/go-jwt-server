package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/api"
)

type Server struct {
}

func NewServer() api.ServerInterface {
	return &Server{}
}

func (s *Server) GetLive(c *gin.Context) {
	c.Status(http.StatusOK)
}

func (s *Server) GetReady(c *gin.Context) {
	c.Status(http.StatusOK)
}
