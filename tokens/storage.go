package tokens

import (
	"github.com/gin-gonic/gin"

	"github.com/spdeepak/go-jwt-server/tokens/repository"
)

type storage struct {
	query repository.Querier
}

type Storage interface {
	saveToken(ctx *gin.Context, token repository.SaveTokenParams) error
	getBearerToken(ctx *gin.Context, token string) (repository.Token, error)
	getRefreshToken(ctx *gin.Context, token string) (repository.Token, error)
	revokeBearerToken(ctx *gin.Context, token string) error
	revokeRefreshToken(ctx *gin.Context, token string) error
	revokeAllToken(ctx *gin.Context, email string) error
	isBearerValid(ctx *gin.Context, bearerValidParams repository.IsBearerValidParams) (bool, error)
	isRefreshValid(ctx *gin.Context, refreshValidParams repository.IsRefreshValidParams) (bool, error)
	refreshAndInvalidateToken(ctx *gin.Context, arg repository.RefreshAndInvalidateTokenParams) error
	listAllActiveSessions(ctx *gin.Context, email string) ([]repository.Token, error)
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

func (s *storage) isBearerValid(ctx *gin.Context, bearerValidParams repository.IsBearerValidParams) (bool, error) {
	res, err := s.query.IsBearerValid(ctx, bearerValidParams)
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (s *storage) isRefreshValid(ctx *gin.Context, refreshValidParams repository.IsRefreshValidParams) (bool, error) {
	res, err := s.query.IsRefreshValid(ctx, refreshValidParams)
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (s *storage) refreshAndInvalidateToken(ctx *gin.Context, arg repository.RefreshAndInvalidateTokenParams) error {
	return s.query.RefreshAndInvalidateToken(ctx, arg)
}

func (s *storage) listAllActiveSessions(ctx *gin.Context, email string) ([]repository.Token, error) {
	return s.query.ListAllActiveSessions(ctx, email)
}
