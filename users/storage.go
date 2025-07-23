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
	GetUserByEmailForAuth(ctx context.Context, email string) (repository.GetEntireUserByEmailRow, error)
	GetUserById(ctx context.Context, userId uuid.UUID) (repository.User, error)
	UserSignupWith2FA(ctx context.Context, arg repository.SignupWith2FAParams) error
	GetUserRolesAndPermissionsFromID(ctx context.Context, id uuid.UUID) (repository.GetUserRolesAndPermissionsFromIDRow, error)
	AssignPermissionToUser(ctx context.Context, arg repository.AssignPermissionToUserParams) error
	AssignRolesToUser(ctx context.Context, arg repository.AssignRolesToUserParams) error
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

func (s *storage) GetUserByEmailForAuth(ctx context.Context, email string) (repository.GetEntireUserByEmailRow, error) {
	return s.userRepository.GetEntireUserByEmail(ctx, email)
}

func (s *storage) GetUserById(ctx context.Context, userId uuid.UUID) (repository.User, error) {
	return s.userRepository.GetUserById(ctx, userId)
}

func (s *storage) GetUserRolesAndPermissionsFromID(ctx context.Context, id uuid.UUID) (repository.GetUserRolesAndPermissionsFromIDRow, error) {
	return s.userRepository.GetUserRolesAndPermissionsFromID(ctx, id)
}

func (s *storage) AssignPermissionToUser(ctx context.Context, arg repository.AssignPermissionToUserParams) error {
	return s.userRepository.AssignPermissionToUser(ctx, arg)
}

func (s *storage) AssignRolesToUser(ctx context.Context, arg repository.AssignRolesToUserParams) error {
	return s.userRepository.AssignRolesToUser(ctx, arg)
}
