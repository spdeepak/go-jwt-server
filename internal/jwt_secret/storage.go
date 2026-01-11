package jwt_secret

import (
	"context"
	"log/slog"
	"os"

	"github.com/spdeepak/go-jwt-server/internal/jwt_secret/repository"
)

type storage struct {
	jwtSecretRepository repository.Querier
}

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
		slog.ErrorContext(ctx, "JWT_TOKEN_SECRET not provided. Could not create default jwt secret.")
		os.Exit(1)
	}
	return nil
}

func (s *storage) getDefaultEncryptedSecret(ctx context.Context) (string, error) {
	jwtSecret, err := s.jwtSecretRepository.GetDefaultSecret(ctx)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return "", nil
		}
		return "", err
	}
	return jwtSecret.Secret, nil
}
