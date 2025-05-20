package jwt_secret

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/jwt_secret/repository"
)

type storage struct {
	jwtSecretRepository *repository.Queries
}

//go:generate go tool mockery --name Storage --filename storage_mock.gen.go --inpackage
type Storage interface {
	GetOrCreateDefaultSecret(ctx context.Context, secret string) (string, error)
}

func NewStorage(jwtSecretRepository *repository.Queries) Storage {
	return &storage{
		jwtSecretRepository: jwtSecretRepository,
	}
}

func (s *storage) GetOrCreateDefaultSecret(ctx context.Context, secret string) (string, error) {
	defaultSecret, err := s.jwtSecretRepository.GetDefaultSecret(ctx)
	if err != nil {
		if err := s.jwtSecretRepository.CreateDefaultSecret(ctx, secret); err != nil {
			log.Fatal().Msg("JWT_TOKEN_SECRET not provided. Could not create default jwt secret.")
		}
		return secret, nil
	}
	return defaultSecret.Secret, nil
}
