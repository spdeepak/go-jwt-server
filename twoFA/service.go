package twoFA

import (
	"encoding/base64"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
	_ "github.com/skip2/go-qrcode"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/twoFA/repository"
)

type service struct {
	appName string
	storage Storage
}

type Service interface {
	Setup2FA(ctx *gin.Context, email string) (User2FASetup, error)
	Verify2FALogin(ctx *gin.Context, params api.Login2FAParams, userId uuid.UUID, passcode string) (bool, error)
	Remove2FA(ctx *gin.Context, userId uuid.UUID, passcode string) error
}

func NewService(appName string, storage Storage) Service {
	return &service{
		appName: appName,
		storage: storage,
	}
}

func (s *service) Setup2FA(ctx *gin.Context, email string) (User2FASetup, error) {
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

func (s *service) Verify2FALogin(ctx *gin.Context, params api.Login2FAParams, userId uuid.UUID, passcode string) (bool, error) {
	twoFADetails, err := s.storage.get2FADetails(ctx, userId)
	if err != nil {
		log.Err(err).Msgf("Failed to get 2FA details for user: %s", userId)
		return false, httperror.New(httperror.InvalidTwoFA)
	}
	return totp.ValidateCustom(passcode, twoFADetails.Secret, time.Now(), totp.ValidateOpts{
		Period:    30, // typical for authenticator apps
		Skew:      1,  // allow ±1 interval (30s) clock drift
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1, // standard
	})
}

func (s *service) Remove2FA(ctx *gin.Context, userId uuid.UUID, passcode string) error {
	twoFADetails, err := s.storage.get2FADetails(ctx, userId)
	if err != nil {
		log.Err(err).Msgf("Failed to get 2FA details for user: %s", userId)
		return httperror.New(httperror.InvalidTwoFA)
	}
	is2FAValid, err := totp.ValidateCustom(passcode, twoFADetails.Secret, time.Now(), totp.ValidateOpts{
		Period:    30, // typical for authenticator apps
		Skew:      1,  // allow ±1 interval (30s) clock drift
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1, // standard
	})
	if err != nil {
		log.Err(err).Msgf("Error during 2FA validation for user: %s", userId)
		return httperror.New(httperror.InvalidTwoFA)
	}
	if !is2FAValid {
		log.Err(err).Msgf("Invalid 2FA code for user: %s", userId)
		return httperror.New(httperror.InvalidTwoFA)
	}
	if err = s.storage.delete2FA(ctx, repository.Delete2FAParams{UserID: userId, Secret: twoFADetails.Secret}); err != nil {
		log.Err(err).Msgf("Failed to delete 2FA setup for user: %s", userId)
		return err
	}
	return nil
}
