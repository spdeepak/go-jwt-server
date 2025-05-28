package users

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens"
	token "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/twoFA"
	"github.com/spdeepak/go-jwt-server/users/repository"
	"golang.org/x/crypto/bcrypt"
)

type service struct {
	storage      Storage
	tokenService tokens.Service
	twoFAService twoFA.Service
}

type Service interface {
	Signup(ctx *gin.Context, user api.UserSignup) (api.SignUpWith2FAResponse, error)
	Login(ctx *gin.Context, params api.LoginParams, login api.UserLogin) (any, error)
	Login2FA(ctx *gin.Context, params api.Login2FAParams, userId, passcode string) (api.LoginSuccessWithJWT, error)
	RefreshToken(ctx *gin.Context, params api.RefreshParams, refresh api.Refresh) (api.LoginSuccessWithJWT, error)
}

func NewService(storage Storage, twoFAService twoFA.Service, tokenService tokens.Service) Service {
	return &service{
		storage:      storage,
		twoFAService: twoFAService,
		tokenService: tokenService,
	}
}

func (s *service) Signup(ctx *gin.Context, user api.UserSignup) (api.SignUpWith2FAResponse, error) {
	hashPassword, err := hashPassword(user.Password)
	if err != nil {
		log.Err(err).Msgf("Failed to encrypt password")
		return api.SignUpWith2FAResponse{}, err
	}
	email := string(user.Email)
	if !user.TwoFAEnabled {
		userSignup := repository.SignupParams{
			Email:        email,
			FirstName:    user.FirstName,
			LastName:     user.LastName,
			Password:     hashPassword,
			TwoFaEnabled: user.TwoFAEnabled,
		}
		if err = s.storage.UserSignup(ctx, userSignup); err != nil {
			if err.Error() == "ERROR: duplicate key value violates unique constraint \"users_email_key\" (SQLSTATE 23505)" {
				return api.SignUpWith2FAResponse{}, httperror.New(httperror.UserAlreadyExists)
			}
			return api.SignUpWith2FAResponse{}, httperror.New(httperror.UserSignUpFailed)
		}
		return api.SignUpWith2FAResponse{}, nil
	}

	user2FASetup, err := s.twoFAService.Setup2FA(ctx, email)
	if err != nil {
		return api.SignUpWith2FAResponse{}, err
	}
	userSignupWith2FA := repository.SignupWith2FAParams{
		Secret:       user2FASetup.Secret,
		Url:          user2FASetup.Url,
		Email:        email,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		Password:     hashPassword,
		TwoFaEnabled: user.TwoFAEnabled,
	}
	err = s.storage.UserSignupWith2FA(ctx, userSignupWith2FA)
	if err != nil {
		if err.Error() == "ERROR: duplicate key value violates unique constraint \"users_email_key\" (SQLSTATE 23505)" {
			return api.SignUpWith2FAResponse{}, httperror.New(httperror.UserAlreadyExists)
		}
		return api.SignUpWith2FAResponse{}, httperror.New(httperror.UserSignUpWith2FAFailed)
	}
	return api.SignUpWith2FAResponse{
		QrImage: user2FASetup.QrImage,
		Secret:  user2FASetup.Secret,
	}, nil
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
		return s.tokenService.GenerateTempToken(ctx, user.ID)
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

func (s *service) Login2FA(ctx *gin.Context, params api.Login2FAParams, userId, passcode string) (api.LoginSuccessWithJWT, error) {
	isValid, err := s.twoFAService.Verify2FALogin(ctx, params, userId, passcode)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.InvalidTwoFA, err.Error())
	}
	if !isValid {
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidTwoFA)
	}

	user, err := s.storage.GetUserById(ctx, uuid.MustParse(userId))
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidCredentials)
		}
		return api.LoginSuccessWithJWT{}, httperror.NewWithStatus(httperror.UndefinedErrorCode, err.Error(), http.StatusBadRequest)
	}

	if user.Locked {
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.UserAccountLocked)
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
