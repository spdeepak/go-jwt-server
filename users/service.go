package users

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/jwt_secret"
	secret "github.com/spdeepak/go-jwt-server/jwt_secret/repository"
	"github.com/spdeepak/go-jwt-server/users/repository"
	"golang.org/x/crypto/bcrypt"
)

type service struct {
	storage          Storage
	jwtSecretService jwt_secret.Service
}

type Service interface {
	Signup(ctx context.Context, user api.UserSignup) error
	Login(ctx context.Context, login api.UserLogin) (api.LoginResponse, error)
	RefreshToken(ctx context.Context, refresh api.Refresh) (api.LoginResponse, error)
}

func NewService(storage Storage, jwtSecretService jwt_secret.Service) Service {
	return &service{
		storage:          storage,
		jwtSecretService: jwtSecretService,
	}
}

func (s *service) Signup(ctx context.Context, user api.UserSignup) error {
	hashPassword, err := hashPassword(user.Password)
	if err != nil {
		log.Err(err).Msgf("Failed to encrypt password")
		return err
	}
	userSignup := repository.SignupParams{
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Password:  hashPassword,
	}
	return s.storage.UserSignup(ctx, userSignup)
}

func (s *service) Login(ctx context.Context, login api.UserLogin) (api.LoginResponse, error) {
	user, err := s.storage.GetUser(ctx, login.Email)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return api.LoginResponse{}, httperror.New(httperror.InvalidCredentials)
		}
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	if validPassword(login.Password, user.Password) {
		jwtUser := secret.User{
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		}
		return s.jwtSecretService.GenerateTokenPair(jwtUser)
	}
	return api.LoginResponse{}, httperror.New(httperror.InvalidCredentials)
}

func (s *service) RefreshToken(ctx context.Context, refresh api.Refresh) (api.LoginResponse, error) {
	_, claims, err := s.jwtSecretService.VerifyRefreshToken(refresh.RefreshToken)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	email, ok := claims["email"].(string)
	if !ok {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.InvalidRefreshToken, "Invalid token claims")
	}

	user, err := s.storage.GetUser(ctx, email)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.InvalidRefreshToken, "Invalid token claims")
	}
	jwtUser := secret.User{
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}
	return s.jwtSecretService.GenerateTokenPair(jwtUser)
}

// hashPassword hashes the plaintext password using bcrypt
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// validPassword compares plaintext and hashed password
func validPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
