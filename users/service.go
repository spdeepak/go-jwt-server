package users

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens"
	token "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/users/repository"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/url"
	"time"
)

type service struct {
	storage      Storage
	tokenService tokens.Service
	redisClient  *db.RedisClient
	recaptchaSecret string
}

type Service interface {
	Signup(ctx *gin.Context, user api.UserSignup) error
	Login(ctx *gin.Context, params api.LoginParams, login api.UserLogin) (api.TokenResponse, error)
	RefreshToken(ctx *gin.Context, params api.RefreshParams, refresh api.Refresh) (api.TokenResponse, error)
	IsLoginLimitReached(ctx context.Context, ip string) (bool, error)
}

func NewService(storage Storage, tokenService tokens.Service, redisClient *db.RedisClient, recaptchaSecret string) Service {
	return &service{
		storage:      storage,
		tokenService: tokenService,
		redisClient:  redisClient,
		recaptchaSecret: recaptchaSecret,
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

const maxLoginAttempts = 3

func (s *service) IsLoginLimitReached(ctx context.Context, ip string) (bool, error) {
	failures, err := s.redisClient.GetLoginFailures(ctx, ip)
	if err != nil {
		return false, err
	}
	return failures >= maxLoginAttempts, nil
}

func (s *service) verifyRecaptcha(ctx context.Context, captchaResponse string) error {
	if captchaResponse == "" {
		return fmt.Errorf("captcha response is required")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.PostForm("https://www.google.com/recaptcha/api/siteverify",
		url.Values{
			"secret":   {s.recaptchaSecret},
			"response": {captchaResponse},
		})
	if err != nil {
		return fmt.Errorf("failed to verify captcha: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode captcha response: %v", err)
	}

	if !result.Success {
		return fmt.Errorf("invalid captcha response")
	}
	return nil
}

func (s *service) Login(ctx *gin.Context, params api.LoginParams, login api.UserLogin) (api.TokenResponse, error) {
	ip := ctx.ClientIP()
	
	// Check if we need to require captcha
	limitReached, err := s.IsLoginLimitReached(ctx, ip)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check login limit")
		return api.TokenResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, "Failed to check login limit")
	}

	// If limit is reached, verify captcha
	if limitReached {
		captchaResponse := ctx.GetHeader("X-Recaptcha-Response")
		if err := s.verifyRecaptcha(ctx, captchaResponse); err != nil {
			return api.TokenResponse{}, httperror.NewWithMetadata(httperror.InvalidCredentials, "Captcha verification required")
		}
	}

	user, err := s.storage.GetUser(ctx, login.Email)
	if err != nil {
		// Increment failed login attempts
		if _, err := s.redisClient.IncrementLoginFailures(ctx, ip); err != nil {
			log.Error().Err(err).Msg("Failed to increment login failures")
		}

		if err.Error() == "sql: no rows in result set" {
			return api.TokenResponse{}, httperror.New(httperror.InvalidCredentials)
		}
		return api.TokenResponse{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	if validPassword(login.Password, user.Password) {
		// Reset failed login attempts on successful login
		if err := s.redisClient.ResetLoginFailures(ctx, ip); err != nil {
			log.Error().Err(err).Msg("Failed to reset login failures")
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

	// Increment failed login attempts
	if _, err := s.redisClient.IncrementLoginFailures(ctx, ip); err != nil {
		log.Error().Err(err).Msg("Failed to increment login failures")
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
