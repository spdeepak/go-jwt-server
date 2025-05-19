package users

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
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
		return api.LoginResponse{}, err
	}
	if validPassword(login.Password, user.Password) {
		return s.jwtSecretService.GenerateTokenPair(login.Email)
	}
	return api.LoginResponse{}, err
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
