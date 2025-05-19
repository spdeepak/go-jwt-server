package users

import (
	"context"

	"github.com/spdeepak/go-jwt-server/users/repository"
)

type storage struct {
	userRepository *repository.Queries
}

type Storage interface {
	UserSignup(ctx context.Context, arg repository.SignupParams) error
	GetUser(ctx context.Context, email string) (repository.User, error)
}

func NewStorage(userRepository *repository.Queries) Storage {
	return &storage{
		userRepository: userRepository,
	}
}

func (s *storage) UserSignup(ctx context.Context, arg repository.SignupParams) error {
	return s.userRepository.Signup(ctx, arg)
}

func (s *storage) GetUser(ctx context.Context, email string) (repository.User, error) {
	return s.userRepository.UserLogin(ctx, email)
}
