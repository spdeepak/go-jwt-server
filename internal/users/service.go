package users

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"github.com/spdeepak/go-jwt-server/api"
	"github.com/spdeepak/go-jwt-server/internal/error"
	"github.com/spdeepak/go-jwt-server/internal/tokens"
	token "github.com/spdeepak/go-jwt-server/internal/tokens/repository"
	"github.com/spdeepak/go-jwt-server/internal/twoFA"
	"github.com/spdeepak/go-jwt-server/internal/users/repository"
	"github.com/spdeepak/go-jwt-server/util"
)

type service struct {
	storage      repository.Querier
	tokenService tokens.Service
	twoFAService twoFA.Service
}

type Service interface {
	Signup(ctx *gin.Context, user api.UserSignup) (api.SignUpWith2FAResponse, error)
	Login(ctx *gin.Context, params api.LoginParams, login api.UserLogin) (any, error)
	Login2FA(ctx *gin.Context, params api.Login2FAParams, userId uuid.UUID, passcode string) (api.LoginSuccessWithJWT, error)
	RefreshToken(ctx *gin.Context, params api.RefreshParams, refresh api.Refresh) (api.LoginSuccessWithJWT, error)
	GetUserRolesAndPermissions(ctx *gin.Context, id api.UuId, params api.GetRolesOfUserParams) (api.UserWithRoles, error)
	AssignRolesToUser(ctx *gin.Context, userId api.UuId, params api.AssignRolesToUserParams, assignRoleToUser api.AssignRoleToUser, email string) error
	UnassignRolesOfUser(ctx *gin.Context, userId api.UuId, roleId api.RoleId, params api.RemoveRolesForUserParams) error
}

func NewService(storage repository.Querier, twoFAService twoFA.Service, tokenService tokens.Service) Service {
	return &service{
		storage:      storage,
		twoFAService: twoFAService,
		tokenService: tokenService,
	}
}

func (s *service) Signup(ctx *gin.Context, user api.UserSignup) (api.SignUpWith2FAResponse, error) {
	hashedPassword, err := hashPassword(user.Password)
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
			Password:     hashedPassword,
			TwoFaEnabled: user.TwoFAEnabled,
		}
		if err = s.storage.Signup(ctx, userSignup); err != nil {
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
		Password:     hashedPassword,
		TwoFaEnabled: user.TwoFAEnabled,
	}
	err = s.storage.SignupWith2FA(ctx, userSignupWith2FA)
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
	user, err := s.storage.GetEntireUserByEmail(ctx, login.Email)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidCredentials)
		}
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.UndefinedErrorCode, err.Error())
	}

	if !validPassword(login.Password, user.Password) {
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidCredentials)
	}
	if user.TwoFaEnabled {
		return s.tokenService.GenerateTempToken(ctx, user.UserID.Bytes)
	}
	if user.Locked {
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.UserAccountLocked)
	}
	jwtUser := token.User{
		ID:        user.UserID,
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

func (s *service) Login2FA(ctx *gin.Context, params api.Login2FAParams, userId uuid.UUID, passcode string) (api.LoginSuccessWithJWT, error) {
	pgtypeUUID := util.UUIDToPgtypeUUID(userId)
	isValid, err := s.twoFAService.Verify2FALogin(ctx, params, pgtypeUUID, passcode)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.InvalidTwoFA, err.Error())
	}
	if !isValid {
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidTwoFA)
	}

	user, err := s.storage.GetUserById(ctx, pgtypeUUID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return api.LoginSuccessWithJWT{}, httperror.New(httperror.InvalidCredentials)
		}
		return api.LoginSuccessWithJWT{}, httperror.NewWithStatus(httperror.UndefinedErrorCode, err.Error(), http.StatusBadRequest)
	}

	if user.Locked {
		return api.LoginSuccessWithJWT{}, httperror.New(httperror.UserAccountLocked)
	}

	jwtUser := token.User{
		ID:        user.ID,
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

	user, err := s.storage.GetEntireUserByEmail(ctx, email)
	if err != nil {
		return api.LoginSuccessWithJWT{}, httperror.NewWithMetadata(httperror.InvalidRefreshToken, "Invalid token claims")
	}
	jwtUser := token.User{
		ID:        user.UserID,
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

func (s *service) GetUserRolesAndPermissions(ctx *gin.Context, id api.UuId, params api.GetRolesOfUserParams) (api.UserWithRoles, error) {
	userRolesAndPermissions, err := s.storage.GetUserRolesAndPermissionsFromID(ctx, util.UUIDToPgtypeUUID(id))
	if err != nil {
		return api.UserWithRoles{}, err
	}
	return api.UserWithRoles{
		Id:          userRolesAndPermissions.UserID.Bytes,
		Email:       openapi_types.Email(userRolesAndPermissions.Email),
		FirstName:   userRolesAndPermissions.FirstName,
		LastName:    userRolesAndPermissions.LastName,
		Permissions: util.SliceSplit(userRolesAndPermissions.PermissionNames.(string), ", "),
		Roles:       util.SliceSplit(userRolesAndPermissions.RoleNames.(string), ", "),
	}, nil
}

func (s *service) AssignRolesToUser(ctx *gin.Context, userId api.UuId, params api.AssignRolesToUserParams, assignRoleToUser api.AssignRoleToUser, email string) error {
	rolesIds := make([]pgtype.UUID, len(assignRoleToUser.Roles))
	for index, id := range assignRoleToUser.Roles {
		rolesIds[index] = util.UUIDToPgtypeUUID(id)
	}
	assignRolesToUser := repository.AssignRolesToUserParams{
		UserID:    util.UUIDToPgtypeUUID(userId),
		RoleID:    rolesIds,
		CreatedBy: email,
	}
	if err := s.storage.AssignRolesToUser(ctx, assignRolesToUser); err != nil {
		return err
	}
	return nil
}

func (s *service) UnassignRolesOfUser(ctx *gin.Context, userId api.UuId, roleId api.RoleId, params api.RemoveRolesForUserParams) error {
	unassignRolesToUser := repository.UnassignRolesToUserParams{
		UserID: util.UUIDToPgtypeUUID(userId),
		RoleID: util.UUIDToPgtypeUUID(roleId),
	}
	err := s.storage.UnassignRolesToUser(ctx, unassignRolesToUser)
	if err != nil {
		return err
	}
	return nil
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
