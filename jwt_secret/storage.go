package jwt_secret

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/jwt_secret/repository"
)

type storage struct {
	jwtSecretRepository repository.Querier
}

//go:generate go tool mockery --name Storage --filename storage_mock.gen.go --inpackage
type Storage interface {
	saveDefaultSecret(ctx context.Context, secret string) error
	getDefaultEncryptedSecret(ctx context.Context) (string, error)
}

func NewStorage(jwtSecretRepository repository.Querier) Storage {
	return &storage{
		jwtSecretRepository: jwtSecretRepository,
	}
}

func (s *storage) saveDefaultSecret(ctx context.Context, secret string) error {
	if err := s.jwtSecretRepository.CreateDefaultSecret(ctx, secret); err != nil {
		log.Fatal().Msg("JWT_TOKEN_SECRET not provided. Could not create default jwt secret.")
	}
	return nil
}

func (s *storage) getDefaultEncryptedSecret(ctx context.Context) (string, error) {
	defaultSecret, err := s.jwtSecretRepository.GetDefaultSecret(ctx)
	if err != nil {
		return "", err
	}
	return defaultSecret.Secret, nil
}
