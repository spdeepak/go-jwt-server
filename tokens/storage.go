package tokens

import (
	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/tokens/repository"
)

type storage struct {
	query repository.Querier
}

type Storage interface {
	SaveToken(ctx *gin.Context, token repository.SaveTokenParams) error
	GetBearerToken(ctx *gin.Context, token string) (repository.Token, error)
	GetRefreshToken(ctx *gin.Context, token string) (repository.Token, error)
	RevokeBearerToken(ctx *gin.Context, token string) error
	RevokeRefreshToken(ctx *gin.Context, token string) error
}

func NewStorage(query repository.Querier) Storage {
	return &storage{
		query: query,
	}
}

func (s *storage) SaveToken(ctx *gin.Context, token repository.SaveTokenParams) error {
	return s.query.SaveToken(ctx, token)
}

func (s *storage) GetBearerToken(ctx *gin.Context, token string) (repository.Token, error) {
	return s.query.GetByBearerToken(ctx, token)
}

func (s *storage) GetRefreshToken(ctx *gin.Context, token string) (repository.Token, error) {
	return s.query.GetByRefreshToken(ctx, token)
}

func (s *storage) RevokeBearerToken(ctx *gin.Context, token string) error {
	return s.query.RevokeBearerToken(ctx, token)
}

func (s *storage) RevokeRefreshToken(ctx *gin.Context, token string) error {
	return s.query.RevokeRefreshToken(ctx, token)
}
