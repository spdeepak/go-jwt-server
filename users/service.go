package users

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	GetUser(ctx *gin.Context, userId string) (repository.User, error)
	Signup(ctx *gin.Context, user api.UserSignup) error
	Login(ctx *gin.Context, params api.LoginParams, login api.UserLogin) (any, error)
	RefreshToken(ctx *gin.Context, params api.RefreshParams, refresh api.Refresh) (api.LoginSuccessWithJWT, error)
}

func NewService(storage Storage, tokenService tokens.Service) Service {
	return &service{
		storage:      storage,
		tokenService: tokenService,
	}
}

func (s *service) GetUser(ctx *gin.Context, userId string) (repository.User, error) {
	user, err := s.storage.GetUserById(ctx, uuid.MustParse(userId))
	if err != nil {
		log.Err(err).Msgf("Failed to get user with id %s", userId)
		return repository.User{}, err
	}
	return user, nil
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

func (s *service) Login(ctx *gin.Context, params api.LoginParams, login api.UserLogin) (any, error) {
	user, err := s.storage.GetUserByEmail(ctx, login.Email)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidCredentials)
		}
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	if !validPassword(login.Password, user.Password) {
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidCredentials)
	}
	if user.TwoFaEnabled {
		return s.tokenService.GenerateTempToken(ctx, user.ID.String())
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
	return s.tokenService.GenerateNewTokenPair(ctx, tokenParams, jwtUser)
}

func (s *service) RefreshToken(ctx *gin.Context, params api.RefreshParams, refresh api.Refresh) (api.LoginSuccessWithJWT, error) {
	claims, err := s.tokenService.ValidateRefreshToken(ctx, params, refresh.RefreshToken)
	if err != nil {
		return api.LoginSuccessWithJWT{}, err
	}
	email, ok := claims["email"].(string)
	if !ok {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.InvalidRefreshToken, "Invalid token claims")
	}

	user, err := s.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.InvalidRefreshToken, "Invalid token claims")
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
