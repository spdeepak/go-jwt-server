package users

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/jwt_secret"
	"github.com/spdeepak/go-jwt-server/users/repository"
	"golang.org/x/crypto/bcrypt"
)

type service struct {
	storage          Storage
	jwtSecretService jwt_secret.Service
}

type Service interface {
	Signup(ctx *gin.Context, user api.UserSignup) error
	Login(c *gin.Context, login api.UserLogin) (api.LoginResponse, error)
	RefreshToken(c *gin.Context, refresh api.Refresh) (api.LoginResponse, error)
}

func NewService(storage Storage, jwtSecretService jwt_secret.Service) Service {
	return &service{
		storage:          storage,
		jwtSecretService: jwtSecretService,
	}
}

func (s *service) Signup(ctx *gin.Context, user api.UserSignup) error {
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

func (s *service) Login(c *gin.Context, login api.UserLogin) (api.LoginResponse, error) {
	user, err := s.storage.GetUser(c, login.Email)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return api.LoginResponse{}, httperror.New(httperror.InvalidCredentials)
		}
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	if validPassword(login.Password, user.Password) {
		return s.jwtSecretService.GenerateTokenPair(user)
	}
	return api.LoginResponse{}, httperror.New(httperror.InvalidCredentials)
}

func (s *service) RefreshToken(c *gin.Context, refresh api.Refresh) (api.LoginResponse, error) {
	_, claims, err := s.jwtSecretService.VerifyToken(refresh.RefreshToken)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	email, ok := claims["email"].(string)
	if !ok {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.InvalidRefreshToken, "Invalid token claims")
	}

	user, err := s.storage.GetUser(c, email)
	if err != nil {
		return api.LoginResponse{}, httperror.NewWithMetadata(httperror.InvalidRefreshToken, "Invalid token claims")
	}
	return s.jwtSecretService.GenerateTokenPair(user)
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
