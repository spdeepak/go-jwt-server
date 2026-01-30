package twoFA

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	_ "github.com/skip2/go-qrcode"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/twoFA/repository"
)

type service struct {
	appName string
	query   repository.Querier
}

type Service interface {
	Setup2FA(ctx context.Context, email string) (User2FASetup, error)
	Verify2FALogin(ctx context.Context, params api.Login2FAParams, userId pgtype.UUID, passcode string) (bool, error)
	Remove2FA(ctx context.Context, userId pgtype.UUID, passcode string) error
}

func NewService(appName string, query repository.Querier) Service {
	return &service{
		appName: appName,
		query:   query,
	}
}

func (s *service) Setup2FA(ctx context.Context, email string) (User2FASetup, error) {
	//Generate secret using the given app name as issues
	//and use email for the account name
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.appName,
		AccountName: email,
	})
	if err != nil {
		return User2FASetup{}, httperror.NewWithMetadata(httperror.TwoFACreateFailed, err.Error())
	}

	//Generate QR code image for the secret URL
	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return User2FASetup{}, httperror.NewWithMetadata(httperror.TwoFACreateFailed, err.Error())
	}
	base64Image := base64.StdEncoding.EncodeToString(png)

	return User2FASetup{
		Secret:  key.Secret(),
		QrImage: "data:image/png;base64," + base64Image,
		Url:     key.URL(),
	}, nil
}

func (s *service) Verify2FALogin(ctx context.Context, params api.Login2FAParams, userId pgtype.UUID, passcode string) (bool, error) {
	twoFADetails, err := s.query.Get2FADetails(ctx, userId)
	if err != nil {
		slog.ErrorContext(ctx, fmt.Sprintf("Failed to get 2FA details for user: %s", userId), slog.Any("error", err))
		return false, httperror.New(httperror.InvalidTwoFA)
	}
	return totp.ValidateCustom(passcode, twoFADetails.Secret, time.Now(), totp.ValidateOpts{
		Period:    30, // typical for authenticator apps
		Skew:      1,  // allow ±1 interval (30s) clock drift
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1, // standard
	})
}

func (s *service) Remove2FA(ctx context.Context, userId pgtype.UUID, passcode string) error {
	twoFADetails, err := s.query.Get2FADetails(ctx, userId)
	if err != nil {
		slog.ErrorContext(ctx, fmt.Sprintf("Failed to get 2FA details for user: %s", userId), slog.Any("error", err))
		return httperror.New(httperror.InvalidTwoFA)
	}
	is2FAValid, err := totp.ValidateCustom(passcode, twoFADetails.Secret, time.Now(), totp.ValidateOpts{
		Period:    30, // typical for authenticator apps
		Skew:      1,  // allow ±1 interval (30s) clock drift
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1, // standard
	})
	if err != nil {
		slog.ErrorContext(ctx, fmt.Sprintf("Error during 2FA validation for user: %s", userId), slog.Any("error", err))
		return httperror.New(httperror.InvalidTwoFA)
	}
	if !is2FAValid {
		slog.ErrorContext(ctx, fmt.Sprintf("Invalid 2FA code for user: %s", userId), slog.Any("error", err))
		return httperror.New(httperror.InvalidTwoFA)
	}
	if err = s.query.Delete2FA(ctx, repository.Delete2FAParams{UserID: userId, Secret: twoFADetails.Secret}); err != nil {
		slog.ErrorContext(ctx, fmt.Sprintf("Failed to delete 2FA setup for user: %s", userId), slog.Any("error", err))
		return err
	}
	return nil
}
