package tokens

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/tokens/repository"
)

const (
	defaultBearerExpiry  = 15 * time.Minute
	defaultRefreshExpiry = 7 * 24 * time.Hour
)

type (
	service struct {
		secret            []byte
		issuer            string
		tokenRepository   repository.Querier
		bearerExpiryTime  time.Duration
		refreshExpiryTime time.Duration
	}
	TokenParams struct {
		XLoginSource string
		UserAgent    string
	}
	Service interface {
		// ValidateRefreshToken verifies if a given refresh token is valid
		ValidateRefreshToken(ctx context.Context, clientIP string, params api.RefreshParams, refreshToken string) (jwt.MapClaims, error)
		// GenerateNewTokenPair Generates a token for a given user
		GenerateNewTokenPair(ctx context.Context, clientIP string, params TokenParams, user repository.User, roles, permissions []string) (api.LoginSuccessWithJWT, error)
		// RefreshAndInvalidateToken Invalidates the given refresh token and generates a new token for the given user
		RefreshAndInvalidateToken(ctx context.Context, clientIP string, params TokenParams, refresh api.Refresh, user repository.User, roles, permissions []string) (api.LoginSuccessWithJWT, error)
		// RevokeRefreshToken marks a refresh token as revoked
		RevokeRefreshToken(ctx context.Context, params api.RevokeRefreshTokenParams, refresh api.RevokeCurrentSession) error
		// RevokeAllTokens marks all refresh tokens of a give user
		RevokeAllTokens(ctx context.Context, email string) error
		// ListActiveSessions list of all active sessions
		ListActiveSessions(ctx context.Context, email string) ([]api.GetAllSessionResponse, error)
		// GenerateTempToken list of all active sessions
		GenerateTempToken(ctx context.Context, userId uuid.UUID) (api.LoginRequires2FA, error)
	}
)

func NewService(tokenRepository repository.Querier, secret []byte, issuer string) Service {
	return &service{
		secret:            secret,
		issuer:            issuer,
		tokenRepository:   tokenRepository,
		bearerExpiryTime:  getOrDefaultExpiry("BEARER_TOKEN_EXPIRY", defaultBearerExpiry),
		refreshExpiryTime: getOrDefaultExpiry("REFRESH_TOKEN_EXPIRY", defaultRefreshExpiry),
	}
}

func getOrDefaultExpiry(env string, defaultExpire time.Duration) time.Duration {
	expireDuration, expireDurationPresent := os.LookupEnv(env)
	if !expireDurationPresent {
		slog.Warn(fmt.Sprintf("%s not present, using default %s", env, defaultExpire))
		return defaultExpire
	} else if expiryTime, err := time.ParseDuration(expireDuration); err != nil {
		return expiryTime
	}
	return defaultExpire
}

func (s *service) ValidateRefreshToken(ctx context.Context, clientIP string, params api.RefreshParams, refreshToken string) (jwt.MapClaims, error) {
	claims, err := s.verifyToken(refreshToken)
	if err != nil {
		return nil, err
	}
	refreshValidParams := repository.IsRefreshValidParams{
		RefreshToken: hash(refreshToken),
		IpAddress:    clientIP,
		UserAgent:    params.UserAgent,
		DeviceName:   "",
	}
	res, err := s.tokenRepository.IsRefreshValid(ctx, refreshValidParams)
	if err != nil {
		return nil, httperror.NewWithMetadata(httperror.RefreshTokenRevoked, err.Error())
	} else if res != 1 { //value of res should be 1 to be valid
		return nil, httperror.New(httperror.RefreshTokenRevoked)
	}
	return claims, nil
}

func (s *service) GenerateNewTokenPair(ctx context.Context, clientIP string, params TokenParams, user repository.User, roles, permissions []string) (api.LoginSuccessWithJWT, error) {
	now := time.Now()
	accessClaims := s.bearerTokenClaims(user, now, roles, permissions)
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
		TokenExpiresAt:   accessClaims.ExpiresAt.Time,
		RefreshExpiresAt: refreshClaims.ExpiresAt.Time,
		IpAddress:        clientIP,
		UserAgent:        params.UserAgent,
		DeviceName:       "",
		Email:            user.Email,
		CreatedBy:        params.XLoginSource,
	}
	err = s.tokenRepository.SaveToken(ctx, saveTokenParams)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.TokenCreationFailed, err.Error())
	}

	return api.LoginSuccessWithJWT{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	}, nil
}

func (s *service) RefreshAndInvalidateToken(ctx context.Context, clientIP string, params TokenParams, refresh api.Refresh, user repository.User, roles, permissions []string) (api.LoginSuccessWithJWT, error) {
	now := time.Now()
	accessClaims := s.bearerTokenClaims(user, now, roles, permissions)
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
		TokenExpiresAt:   accessClaims.ExpiresAt.Time,
		RefreshExpiresAt: refreshClaims.ExpiresAt.Time,
		IpAddress:        clientIP,
		UserAgent:        params.UserAgent,
		DeviceName:       "",
		Email:            user.Email,
		CreatedBy:        params.XLoginSource,
		OldRefreshToken:  hash(refresh.RefreshToken),
	}
	if err := s.tokenRepository.RefreshAndInvalidateToken(ctx, refreshAndInvalidateTokenParams); err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.TokenCreationFailed, err.Error())
	}
	return api.LoginSuccessWithJWT{
		AccessToken:  signedAccessToken,
		RefreshToken: signedRefreshToken,
	}, nil
}

func (s *service) RevokeRefreshToken(ctx context.Context, params api.RevokeRefreshTokenParams, refresh api.RevokeCurrentSession) error {
	hashedRefreshToken := hash(refresh.RefreshToken)
	_, err := s.verifyToken(refresh.RefreshToken)
	if err != nil {
		return err
	}
	err = s.tokenRepository.RevokeRefreshToken(ctx, hashedRefreshToken)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return httperror.New(httperror.InvalidRefreshToken)
		}
		return httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}
	return nil
}

func (s *service) RevokeAllTokens(ctx context.Context, email string) error {
	err := s.tokenRepository.RevokeAllTokens(ctx, email)
	if err != nil {
		return httperror.NewWithMetadata(httperror.TokenRevokeFailed, err.Error())
	}
	return nil
}

func (s *service) ListActiveSessions(ctx context.Context, email string) ([]api.GetAllSessionResponse, error) {
	activeSessions, err := s.tokenRepository.ListAllActiveSessions(ctx, email)
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

func (s *service) GenerateTempToken(ctx context.Context, userId uuid.UUID) (api.LoginRequires2FA, error) {
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

func (s *service) tempTokenClaims(userId uuid.UUID, now time.Time) TokenClaims {
	return TokenClaims{
		Type:      "2FA",
		AuthLevel: "pre-2fa",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userId.String(),
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(5 * time.Minute)},
			NotBefore: &jwt.NumericDate{Time: now},
			IssuedAt:  &jwt.NumericDate{Time: now},
			ID:        uuid.NewString(),
		},
	}
}

func (s *service) bearerTokenClaims(user repository.User, now time.Time, roles, permissions []string) TokenClaims {
	return TokenClaims{
		Name:        user.FirstName + " " + user.LastName,
		Email:       user.Email,
		FirstName:   user.FirstName,
		LastName:    user.LastName,
		Roles:       roles,
		Permissions: permissions,
		Type:        "Bearer",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID.String(),
			ExpiresAt: &jwt.NumericDate{Time: now.Add(s.bearerExpiryTime)},
			NotBefore: &jwt.NumericDate{Time: now},
			IssuedAt:  &jwt.NumericDate{Time: now},
			ID:        uuid.NewString(),
		},
	}
}

func (s *service) refreshTokenClaims(user repository.User, now time.Time) TokenClaims {
	return TokenClaims{
		Email: user.Email,
		Type:  "Refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID.String(),
			ExpiresAt: &jwt.NumericDate{Time: now.Add(s.refreshExpiryTime)},
			NotBefore: &jwt.NumericDate{Time: now},
			IssuedAt:  &jwt.NumericDate{Time: now},
			ID:        uuid.NewString(),
		},
	}
}

func (s *service) verifyToken(tokenStr string) (jwt.MapClaims, error) {
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
