package twoFA

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog/log"
	"github.com/skip2/go-qrcode"
	_ "github.com/skip2/go-qrcode"
	"github.com/spdeepak/go-jwt-server/api"
	httperror "github.com/spdeepak/go-jwt-server/error"
	"github.com/spdeepak/go-jwt-server/tokens"
	tokenRepo "github.com/spdeepak/go-jwt-server/tokens/repository"
	"github.com/spdeepak/go-jwt-server/twoFA/repository"
	"github.com/spdeepak/go-jwt-server/users"
)

type service struct {
	appName      string
	storage      Storage
	userService  users.Service
	tokenService tokens.Service
}

type Service interface {
	GenerateSecret(ctx *gin.Context, email, userId string) (api.TwoFAResponse, error)
	Verify2FALogin(ctx *gin.Context, params api.Verify2FAParams, userId, passcode string) (api.LoginSuccessWithJWT, error)
	Delete2FA(ctx *gin.Context, userId, passcode string) error
}

func NewService(appName string, storage Storage, userService users.Service, tokenService tokens.Service) Service {
	return &service{
		appName:      appName,
		storage:      storage,
		userService:  userService,
		tokenService: tokenService,
	}
}

func (s *service) GenerateSecret(ctx *gin.Context, email, userId string) (api.TwoFAResponse, error) {
	//Generate secret
	key, err := totp.Generate(totp.GenerateOpts{

		Issuer:      s.appName,
		AccountName: fmt.Sprintf("%s:%s", userId, email),
	})
	if err != nil {
		log.Err(err).Msgf("Error during TOTP generation for user: %s", userId)
		return api.TwoFAResponse{}, httperror.NewWithMetadata(httperror.TwoFACreateFailed, err.Error())
	}

	//Save secret to the DB
	createTotpParams := repository.CreateTOTPParams{
		UserID: userId,
		Secret: key.Secret(),
		Url:    key.URL(),
	}
	err = s.storage.create2FA(ctx, createTotpParams)
	if err != nil {
		log.Err(err).Msgf("Error while saving TOTP details for user: %s", userId)
		return api.TwoFAResponse{}, httperror.NewWithMetadata(httperror.TwoFACreateFailed, err.Error())
	}

	//Generate QR code image for the secret URL
	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		defer func() {
			delErr := s.storage.delete2FA(ctx, repository.DeleteSecretParams{UserID: userId, Secret: key.Secret()})
			if delErr != nil {
				log.Error().Any("qrCodeError", err).Any("secretDeleteError", delErr).Msgf("Error while generating QR code from secret URL and deleting created secret for user: %s", userId)
			}
		}()
		log.Err(err).Msgf("Error during QR code generation for user: %s", userId)
		return api.TwoFAResponse{}, httperror.NewWithMetadata(httperror.TwoFACreateFailed, err.Error())
	}
	base64Image := base64.StdEncoding.EncodeToString(png)

	return api.TwoFAResponse{
		QrImage: "data:image/png;base64," + base64Image,
		Secret:  key.Secret(),
	}, nil
}

func (s *service) Verify2FALogin(ctx *gin.Context, params api.Verify2FAParams, userId, passcode string) (api.LoginSuccessWithJWT, error) {
	totpDetails, err := s.storage.get2FADetails(ctx, userId)
	if err != nil {
		log.Err(err).Msgf("Failed to get 2FA details for user: %s", userId)
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidTwoFA)
	}
	isValid, err := totp.ValidateCustom(passcode, totpDetails.Secret, time.Now(), totp.ValidateOpts{
		Period:    30, // typical for authenticator apps
		Skew:      1,  // allow ±1 interval (30s) clock drift
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1, // standard
	})
	if err != nil {
		log.Err(err).Msgf("Invalid 2FA code for user: %s", userId)
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidTwoFA)
	}
	if !isValid {
		log.Error().Msgf("Invalid 2FA code for user: %s", userId)
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidTwoFA)
	}

	user, err := s.userService.GetUser(ctx, userId)
	if err != nil {
		return api.LoginSuccessWithJWT{}, err
	}

	return s.tokenService.GenerateNewTokenPair(ctx, tokens.TokenParams{XLoginSource: string(params.XLoginSource), UserAgent: params.UserAgent}, tokenRepo.User{ID: user.ID, Email: user.Email, FirstName: user.FirstName, LastName: user.LastName})
}

func (s *service) Delete2FA(ctx *gin.Context, userId, passcode string) error {
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
	if is2FAValid {
		if err = s.storage.delete2FA(ctx, repository.DeleteSecretParams{UserID: userId, Secret: twoFADetails.Secret}); err != nil {
			log.Err(err).Msgf("Failed to delete 2FA setup for user: %s", userId)
			return err
		}
		return nil
	}
	log.Err(err).Msgf("Invalid 2FA code for user: %s", userId)
	return httperror.New(httperror.InvalidTwoFA)
}
