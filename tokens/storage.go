package tokens

import (
	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/tokens/repository"
)

type storage struct {
	query repository.Querier
}

//go:generate go tool mockery --name Storage --filename storage_mock.gen.go --inpackage
type Storage interface {
	saveToken(ctx *gin.Context, token repository.SaveTokenParams) error
	getBearerToken(ctx *gin.Context, token string) (repository.Token, error)
	getRefreshToken(ctx *gin.Context, token string) (repository.Token, error)
	revokeBearerToken(ctx *gin.Context, token string) error
	revokeRefreshToken(ctx *gin.Context, token string) error
	revokeAllToken(ctx *gin.Context, email string) error
}

func NewStorage(query repository.Querier) Storage {
	return &storage{
		query: query,
	}
}

func (s *storage) saveToken(ctx *gin.Context, token repository.SaveTokenParams) error {
	return s.query.SaveToken(ctx, token)
}

func (s *storage) getBearerToken(ctx *gin.Context, token string) (repository.Token, error) {
	return s.query.GetByBearerToken(ctx, token)
}

func (s *storage) getRefreshToken(ctx *gin.Context, token string) (repository.Token, error) {
	return s.query.GetByRefreshToken(ctx, token)
}

func (s *storage) revokeBearerToken(ctx *gin.Context, token string) error {
	return s.query.RevokeBearerToken(ctx, token)
}

func (s *storage) revokeRefreshToken(ctx *gin.Context, token string) error {
	return s.query.RevokeRefreshToken(ctx, token)
}

func (s *storage) revokeAllToken(ctx *gin.Context, email string) error {
	return s.query.RevokeAllTokens(ctx, email)
}
