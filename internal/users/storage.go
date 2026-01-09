package users

import (
	"context"

	"github.com/google/uuid"

	repository2 "github.com/spdeepak/go-jwt-server/internal/users/repository"
)

type storage struct {
	userRepository repository2.Querier
}

type Storage interface {
	UserSignup(ctx context.Context, arg repository2.SignupParams) error
	GetUserByEmailForAuth(ctx context.Context, email string) (repository2.GetEntireUserByEmailRow, error)
	GetUserById(ctx context.Context, userId uuid.UUID) (repository2.User, error)
	UserSignupWith2FA(ctx context.Context, arg repository2.SignupWith2FAParams) error
	GetUserRolesAndPermissionsFromID(ctx context.Context, id uuid.UUID) (repository2.GetUserRolesAndPermissionsFromIDRow, error)
	AssignPermissionToUser(ctx context.Context, arg repository2.AssignPermissionToUserParams) error
	AssignRolesToUser(ctx context.Context, arg repository2.AssignRolesToUserParams) error
	UnassignRolesToUser(ctx context.Context, arg repository2.UnassignRolesToUserParams) error
}

func NewStorage(userRepository repository2.Querier) Storage {
	return &storage{
		userRepository: userRepository,
	}
}

func (s *storage) UserSignup(ctx context.Context, arg repository2.SignupParams) error {
	return s.userRepository.Signup(ctx, arg)
}

func (s *storage) UserSignupWith2FA(ctx context.Context, arg repository2.SignupWith2FAParams) error {
	return s.userRepository.SignupWith2FA(ctx, arg)
}

func (s *storage) GetUserByEmailForAuth(ctx context.Context, email string) (repository2.GetEntireUserByEmailRow, error) {
	return s.userRepository.GetEntireUserByEmail(ctx, email)
}

func (s *storage) GetUserById(ctx context.Context, userId uuid.UUID) (repository2.User, error) {
	return s.userRepository.GetUserById(ctx, userId)
}

func (s *storage) GetUserRolesAndPermissionsFromID(ctx context.Context, id uuid.UUID) (repository2.GetUserRolesAndPermissionsFromIDRow, error) {
	return s.userRepository.GetUserRolesAndPermissionsFromID(ctx, id)
}

func (s *storage) AssignPermissionToUser(ctx context.Context, arg repository2.AssignPermissionToUserParams) error {
	return s.userRepository.AssignPermissionToUser(ctx, arg)
}

func (s *storage) AssignRolesToUser(ctx context.Context, arg repository2.AssignRolesToUserParams) error {
	return s.userRepository.AssignRolesToUser(ctx, arg)
}

func (s *storage) UnassignRolesToUser(ctx context.Context, arg repository2.UnassignRolesToUserParams) error {
	return s.userRepository.UnassignRolesToUser(ctx, arg)
}
