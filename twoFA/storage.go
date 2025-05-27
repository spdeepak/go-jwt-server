package twoFA

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/spdeepak/go-jwt-server/twoFA/repository"
)

type storage struct {
	query repository.Querier
}

type Storage interface {
	get2FADetails(ctx *gin.Context, userId uuid.UUID) (repository.Users2fa, error)
	save2FA(ctx *gin.Context, params repository.Setup2FAParams) error
	delete2FA(ctx *gin.Context, params repository.Delete2FAParams) error
}

func NewStorage(query repository.Querier) Storage {
	return &storage{
		query: query,
	}
}

func (s *storage) save2FA(ctx *gin.Context, params repository.Setup2FAParams) error {
	return s.query.Setup2FA(ctx, params)
}

func (s *storage) delete2FA(ctx *gin.Context, params repository.Delete2FAParams) error {
	return s.query.Delete2FA(ctx, params)
}

func (s *storage) get2FADetails(ctx *gin.Context, userId uuid.UUID) (repository.Users2fa, error) {
	return s.query.Get2FADetails(ctx, userId)
}
