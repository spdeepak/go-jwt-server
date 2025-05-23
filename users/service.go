package users

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens"
	token "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/users/repository"
	"golang.org/x/crypto/bcrypt"
)

type service struct {
	storage      Storage
	tokenService tokens.Service
}

type Service interface {
	Signup(ctx *gin.Context, user api.UserSignup) error
	Login(ctx *gin.Context, params api.LoginParams, login api.UserLogin) (api.TokenResponse, error)
	RefreshToken(ctx *gin.Context, params api.RefreshParams, refresh api.Refresh) (api.TokenResponse, error)
}

func NewService(storage Storage, tokenService tokens.Service) Service {
	return &service{
		storage:      storage,
		tokenService: tokenService,
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

func (s *service) Login(ctx *gin.Context, params api.LoginParams, login api.UserLogin) (api.TokenResponse, error) {
	user, err := s.storage.GetUser(ctx, login.Email)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return api.TokenResponse{}, httperror.New(httperror.InvalidCredentials)
		}
		return api.TokenResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	if validPassword(login.Password, user.Password) {
		jwtUser := token.User{
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		}
		tokenParams := tokens.TokenParams{
			XLoginSource: string(params.XLoginSource),
			UserAgent:    params.UserAgent,
		}
		return s.tokenService.GenerateNewTokenPair(ctx, tokenParams, jwtUser)
	}
	return api.TokenResponse{}, httperror.New(httperror.InvalidCredentials)
}

func (s *service) RefreshToken(ctx *gin.Context, params api.RefreshParams, refresh api.Refresh) (api.TokenResponse, error) {
	claims, err := s.tokenService.ValidateRefreshToken(ctx, params, refresh.RefreshToken)
	if err != nil {
		return api.TokenResponse{}, err
	}
	email, ok := claims["email"].(string)
	if !ok {
		return api.TokenResponse{}, httperror.NewWithMetadata(httperror.InvalidRefreshToken, "Invalid token claims")
	}

	user, err := s.storage.GetUser(ctx, email)
	if err != nil {
		return api.TokenResponse{}, httperror.NewWithMetadata(httperror.InvalidRefreshToken, "Invalid token claims")
	}
	jwtUser := token.User{
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}

	tokenParams := tokens.TokenParams{
		XLoginSource: string(params.XLoginSource),
		UserAgent:    params.UserAgent,
	}
	return s.tokenService.RefreshAndInvalidateToken(ctx, tokenParams, refresh, jwtUser)
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
