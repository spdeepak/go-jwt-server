package users

import (
	"context"

	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/users/repository"
)

type storage struct {
	userRepository repository.Querier
}

type Storage interface {
	UserSignup(ctx context.Context, arg repository.SignupParams) error
	GetUserByEmail(ctx context.Context, email string) (repository.User, error)
	GetUserById(ctx context.Context, userId uuid.UUID) (repository.User, error)
	UserSignupWith2FA(ctx context.Context, arg repository.SignupWith2FAParams) error
}

func NewStorage(userRepository repository.Querier) Storage {
	return &storage{
		userRepository: userRepository,
	}
}

func (s *storage) UserSignup(ctx context.Context, arg repository.SignupParams) error {
	return s.userRepository.Signup(ctx, arg)
}

func (s *storage) UserSignupWith2FA(ctx context.Context, arg repository.SignupWith2FAParams) error {
	return s.userRepository.SignupWith2FA(ctx, arg)
}

func (s *storage) GetUserByEmail(ctx context.Context, email string) (repository.User, error) {
	return s.userRepository.GetUserByEmail(ctx, email)
}

func (s *storage) GetUserById(ctx context.Context, userId uuid.UUID) (repository.User, error) {
	return s.userRepository.GetUserById(ctx, userId)
}
