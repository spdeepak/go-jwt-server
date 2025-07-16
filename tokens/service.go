package tokens

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens/repository"
)

const (
	defaultBearerExpiry  = 15 * time.Minute
	defaultRefreshExpiry = 7 * 24 * time.Hour
)

type service struct {
	secret            []byte
	issuer            string
	storage           Storage
	bearerExpiryTime  time.Duration
	refreshExpiryTime time.Duration
}

type TokenParams struct {
	XLoginSource string
	UserAgent    string
}

type Service interface {
	// ValidateRefreshToken verifies if a given refresh token is valid
	ValidateRefreshToken(ctx *gin.Context, params api.RefreshParams, refreshToken string) (jwt.MapClaims, error)
	// GenerateNewTokenPair Generates a token for a given user
	GenerateNewTokenPair(ctx *gin.Context, params TokenParams, user repository.User) (api.LoginSuccessWithJWT, error)
	// RefreshAndInvalidateToken Invalidates the given refresh token and generates a new token for the given user
	RefreshAndInvalidateToken(ctx *gin.Context, params TokenParams, refresh api.Refresh, user repository.User) (api.LoginSuccessWithJWT, error)
	// RevokeRefreshToken marks a refresh token as revoked
	RevokeRefreshToken(ctx *gin.Context, params api.RevokeRefreshTokenParams, refresh api.RevokeCurrentSession) error
	// RevokeAllTokens marks all refresh tokens of a give user
	RevokeAllTokens(ctx *gin.Context, email string) error
	// ListActiveSessions list of all active sessions
	ListActiveSessions(ctx *gin.Context, email string) ([]api.GetAllSessionResponse, error)
	// GenerateTempToken list of all active sessions
	GenerateTempToken(ctx *gin.Context, userId uuid.UUID) (api.LoginRequires2FA, error)
}

func NewService(storage Storage, secret []byte) Service {
	return &service{
		secret:            secret,
		storage:           storage,
		bearerExpiryTime:  getOrDefaultExpiry("BEARER_TOKEN_EXPIRY", defaultBearerExpiry),
		refreshExpiryTime: getOrDefaultExpiry("REFRESH_TOKEN_EXPIRY", defaultRefreshExpiry),
	}
}

func getOrDefaultExpiry(env string, defaultExpire time.Duration) time.Duration {
	expireDuration, expireDurationPresent := os.LookupEnv(env)
	if !expireDurationPresent {
		log.Warn().Msgf("%s not present, using default %s", env, defaultExpire)
		return defaultExpire
	} else if expiryTime, err := time.ParseDuration(expireDuration); err != nil {
		return expiryTime
	}
	return defaultExpire
}

func (s *service) ValidateRefreshToken(ctx *gin.Context, params api.RefreshParams, refreshToken string) (jwt.MapClaims, error) {
	claims, err := s.verifyToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	refreshValidParams := repository.IsRefreshValidParams{
		RefreshToken: hash(refreshToken),
		IpAddress:    ctx.ClientIP(),
		UserAgent:    params.UserAgent,
		DeviceName:   "",
	}
	valid, err := s.storage.isRefreshValid(ctx, refreshValidParams)
	if err != nil {
		return nil, httperror.NewWithMetadata(httperror.RefreshTokenRevoked, err.Error())
	} else if !valid {
		return nil, httperror.New(httperror.RefreshTokenRevoked)
	}
	return claims, nil
}

func (s *service) GenerateNewTokenPair(ctx *gin.Context, params TokenParams, user repository.User) (api.LoginSuccessWithJWT, error) {
	now := time.Now()
	accessClaims := s.bearerTokenClaims(user, now)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString(s.secret)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	refreshClaims := s.refreshTokenClaims(user, now)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString(s.secret)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	saveTokenParams := repository.SaveTokenParams{
		Token:            hash(signedAccessToken),
		RefreshToken:     hash(signedRefreshToken),
		TokenExpiresAt:   time.Unix(accessClaims["exp"].(int64), 0),
		RefreshExpiresAt: time.Unix(refreshClaims["exp"].(int64), 0),
		IpAddress:        ctx.ClientIP(),
		UserAgent:        params.UserAgent,
		DeviceName:       "",
		Email:            user.Email,
		CreatedBy:        params.XLoginSource,
	}
	err = s.storage.saveToken(ctx, saveTokenParams)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.TokenCreationFailed, err.Error())
	}

	return api.LoginSuccessWithJWT{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	}, nil
}

func (s *service) RefreshAndInvalidateToken(ctx *gin.Context, params TokenParams, refresh api.Refresh, user repository.User) (api.LoginSuccessWithJWT, error) {
	now := time.Now()
	accessClaims := s.bearerTokenClaims(user, now)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString(s.secret)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	refreshClaims := s.refreshTokenClaims(user, now)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString(s.secret)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	refreshAndInvalidateTokenParams := repository.RefreshAndInvalidateTokenParams{
		NewToken:         hash(signedAccessToken),
		NewRefreshToken:  hash(signedRefreshToken),
		TokenExpiresAt:   time.Unix(accessClaims["exp"].(int64), 0),
		RefreshExpiresAt: time.Unix(refreshClaims["exp"].(int64), 0),
		IpAddress:        ctx.ClientIP(),
		UserAgent:        params.UserAgent,
		DeviceName:       "",
		Email:            user.Email,
		CreatedBy:        params.XLoginSource,
		OldRefreshToken:  hash(refresh.RefreshToken),
	}
	if err := s.storage.refreshAndInvalidateToken(ctx, refreshAndInvalidateTokenParams); err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.TokenCreationFailed, err.Error())
	}
	return api.LoginSuccessWithJWT{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	}, nil
}

func (s *service) RevokeRefreshToken(ctx *gin.Context, params api.RevokeRefreshTokenParams, refresh api.RevokeCurrentSession) error {
	hashedRefreshToken := hash(refresh.RefreshToken)
	_, err := s.verifyToken(ctx, refresh.RefreshToken)
	if err != nil {
		return err
	}
	err = s.storage.revokeRefreshToken(ctx, hashedRefreshToken)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return httperror.New(httperror.InvalidRefreshToken)
		}
		return httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	return nil
}

func (s *service) RevokeAllTokens(ctx *gin.Context, email string) error {
	err := s.storage.revokeAllToken(ctx, email)
	if err != nil {
		return httperror.NewWithMetadata(httperror.TokenRevokeFailed, err.Error())
	}
	return nil
}

func (s *service) ListActiveSessions(ctx *gin.Context, email string) ([]api.GetAllSessionResponse, error) {
	activeSessions, err := s.storage.listAllActiveSessions(ctx, email)
	if err != nil {
		return nil, httperror.NewWithMetadata(httperror.ActiveSessionsListFailed, err.Error())
	}
	activeSessionResponse := make([]api.GetAllSessionResponse, len(activeSessions))
	for index, activeSession := range activeSessions {
		activeSessionResponse[index] = api.GetAllSessionResponse{
			CreatedBy: activeSession.CreatedBy,
			IpAddress: activeSession.IpAddress,
			IssuedAt:  activeSession.IssuedAt,
			ExpiresAt: activeSession.RefreshExpiresAt,
			UserAgent: activeSession.UserAgent,
		}
	}
	return activeSessionResponse, nil
}

func (s *service) GenerateTempToken(ctx *gin.Context, userId uuid.UUID) (api.LoginRequires2FA, error) {
	now := time.Now()
	tempTokenClaims := s.tempTokenClaims(userId, now)
	tempToken := jwt.NewWithClaims(jwt.SigningMethodHS256, tempTokenClaims)
	signedTempToken, err := tempToken.SignedString(s.secret)
	if err != nil {
		return api.LoginRequires2FA{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	return api.LoginRequires2FA{
		TempToken: signedTempToken,
		Type:      api.N2fa,
	}, nil
}

func (s *service) tempTokenClaims(userId uuid.UUID, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"sub":        userId,
		"typ":        "2FA",
		"iat":        now.Unix(),                             //Issued at
		"exp":        time.Now().Add(5 * time.Minute).Unix(), //Expiration now
		"iss":        s.issuer,                               //Issuer
		"auth_level": "pre-2fa",
	}
}

func (s *service) bearerTokenClaims(user repository.User, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"name":       user.FirstName + " " + user.LastName,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"sub":        user.ID,
		"typ":        "Bearer",                           //Type of token
		"nbf":        now.Unix(),                         //Not valid before
		"iss":        s.issuer,                           //Issuer
		"iat":        now.Unix(),                         //Issued at
		"jti":        uuid.NewString(),                   //JWT ID
		"exp":        now.Add(s.bearerExpiryTime).Unix(), //Expiration now
	}
}

func (s *service) refreshTokenClaims(user repository.User, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"typ":   "Refresh",                           //Type of token
		"nbf":   now.Unix(),                          //Not valid before
		"iss":   s.issuer,                            //Issuer
		"iat":   now.Unix(),                          //Issued at
		"jti":   uuid.NewString(),                    //JWT ID
		"exp":   now.Add(s.refreshExpiryTime).Unix(), //Expiration now
	}
}

func (s *service) verifyToken(ctx *gin.Context, tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return s.secret, nil
	})

	if err != nil {
		return nil, httperror.NewWithMetadata(httperror.Unauthorized, err.Error())
	} else if !token.Valid {
		return nil, httperror.NewWithMetadata(httperror.Unauthorized, "Invalid Refresh Token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		if expTime, ok := claims["exp"].(float64); ok {
			expirationTime := time.Unix(int64(expTime), 0)
			if expirationTime.Before(time.Now()) {
				return nil, httperror.New(httperror.ExpiredRefreshToken)
			}
		} else {
			return nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, "invalid claims")
		}
	} else if !ok || !token.Valid {
		return nil, httperror.NewWithMetadata(httperror.UndefinedErrorCode, "invalid claims")
	}

	return claims, nil
}

func hash(anything string) string {
	h := sha256.New()
	h.Write([]byte(anything))
	return hex.EncodeToString(h.Sum(nil))
}
