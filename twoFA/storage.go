package twoFA

import (
	"github.com/gin-gonic/gin"
	"github.com/spdeepak/go-jwt-server/twofa/repository"
)

type storage struct {
	query repository.Querier
}

type Storage interface {
	get2FADetails(ctx *gin.Context, userId string) (repository.Users2fa, error)
	create2FA(ctx *gin.Context, params repository.CreateTOTPParams) error
	delete2FA(ctx *gin.Context, params repository.DeleteSecretParams) error
}

func NewStorage(query repository.Querier) Storage {
	return &storage{
		query: query,
	}
}

func (s *storage) create2FA(ctx *gin.Context, params repository.CreateTOTPParams) error {
	return s.query.CreateTOTP(ctx, params)
}

func (s *storage) delete2FA(ctx *gin.Context, params repository.DeleteSecretParams) error {
	return s.query.DeleteSecret(ctx, params)
}

func (s *storage) get2FADetails(ctx *gin.Context, userId string) (repository.Users2fa, error) {
	return s.query.GetSecret(ctx, userId)
}
