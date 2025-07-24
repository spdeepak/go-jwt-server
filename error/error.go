package httperror

import (
	"fmt"
	"net/http"
)

type HttpError struct {
	ErrorCode   string `json:"errorCode,omitempty"`
	Description string `json:"description,omitempty"`
	Metadata    string `json:"-"`
	StatusCode  int    `json:"-"`
}

func (e HttpError) Error() string {
	return fmt.Sprintf("errorCode: %s, description: %s,  metadata: %s", e.ErrorCode, e.Description, e.Metadata)
}

const (
	UndefinedErrorCode       = "JWT0000"
	Unauthorized             = "JWT0001"
	InvalidCredentials       = "JWT0002"
	InvalidRefreshToken      = "JWT0003"
	TokenCreationFailed      = "JWT0004"
	ExpiredBearerToken       = "JWT0005"
	BearerTokenMissing       = "JWT0006"
	ExpiredRefreshToken      = "JWT0007"
	BearerTokenRevoked       = "JWT0008"
	RefreshTokenRevoked      = "JWT0009"
	TokenRevokeFailed        = "JWT0010"
	ActiveSessionsListFailed = "JWT0011"
	TwoFACreateFailed        = "JWT0012"
	InvalidTwoFA             = "JWT0013"
	UserSignUpFailed         = "JWT0014"
	UserSignUpWith2FAFailed  = "JWT0015"
	UserAlreadyExists        = "JWT0016"
	UserAccountLocked        = "JWT0017"
	InvalidRequest           = "JWT0018"
	RoleAlreadyExists        = "JWT0019"
	RoleCreationFailed       = "JWT0020"
	RoleDoesntExist          = "JWT0021"
	PermissionAlreadyExists  = "JWT0022"
	PermissionCreationFailed = "JWT0023"
	PermissionDoesntExist    = "JWT0024"
	InvalidRequestBody       = "JWT0025"
)

var httpErrors = map[string]HttpError{
	UndefinedErrorCode: {
		StatusCode:  http.StatusInternalServerError,
		Description: "Unexpected error occurred",
	},
	Unauthorized: {
		StatusCode:  http.StatusUnauthorized,
		Description: "Invalid Bearer token. Please login again.",
	},
	InvalidCredentials: {
		StatusCode:  http.StatusUnauthorized,
		Description: "Invalid username or password",
	},
	InvalidRefreshToken: {
		StatusCode:  http.StatusUnauthorized,
		Description: "Invalid Refresh token",
	},
	TokenCreationFailed: {
		StatusCode:  http.StatusInternalServerError,
		Description: "Token creation failed",
	},
	ExpiredBearerToken: {
		StatusCode:  http.StatusUnauthorized,
		Description: "Bearer token is expired. Please login again.",
	},
	BearerTokenMissing: {
		StatusCode:  http.StatusUnauthorized,
		Description: "Bearer token is missing. Please login again.",
	},
	ExpiredRefreshToken: {
		StatusCode:  http.StatusUnauthorized,
		Description: "Refresh token is expired. Please login again.",
	},
	BearerTokenRevoked: {
		StatusCode:  http.StatusUnauthorized,
		Description: "Bearer token is expired. Please login again.",
	},
	RefreshTokenRevoked: {
		StatusCode:  http.StatusUnauthorized,
		Description: "Refresh token is revoked. Please login again.",
	},
	TokenRevokeFailed: {
		StatusCode:  http.StatusInternalServerError,
		Description: "Refresh token revoke failed.",
	},
	ActiveSessionsListFailed: {
		StatusCode:  http.StatusInternalServerError,
		Description: "Failed to list all active sessions.",
	},
	TwoFACreateFailed: {
		StatusCode:  http.StatusInternalServerError,
		Description: "Failed to setup 2FA. Please try again.",
	},
	InvalidTwoFA: {
		StatusCode:  http.StatusUnauthorized,
		Description: "Invalid 2FA. Please try again.",
	},
	UserSignUpFailed: {
		StatusCode:  http.StatusInternalServerError,
		Description: "User signup failed. Please try again.",
	},
	UserSignUpWith2FAFailed: {
		StatusCode:  http.StatusInternalServerError,
		Description: "User signup with 2FA failed. Please try again.",
	},
	UserAlreadyExists: {
		StatusCode:  http.StatusConflict,
		Description: "User already exists with given email",
	},
	UserAccountLocked: {
		StatusCode:  http.StatusForbidden,
		Description: "User account is locked",
	},
	InvalidRequest: {
		StatusCode:  http.StatusBadRequest,
		Description: "Invalid request",
	},
	RoleAlreadyExists: {
		StatusCode:  http.StatusConflict,
		Description: "Role already exists with given name",
	},
	RoleCreationFailed: {
		StatusCode:  http.StatusInternalServerError,
		Description: "Role creation failed",
	},
	RoleDoesntExist: {
		StatusCode:  http.StatusNotFound,
		Description: "Role doesn't exist",
	},
	PermissionAlreadyExists: {
		StatusCode:  http.StatusConflict,
		Description: "Permission already exists with given name",
	},
	PermissionCreationFailed: {
		StatusCode:  http.StatusInternalServerError,
		Description: "Permission creation failed",
	},
	PermissionDoesntExist: {
		StatusCode:  http.StatusNotFound,
		Description: "Permission doesn't exist",
	},
	InvalidRequestBody: {
		StatusCode:  http.StatusBadRequest,
		Description: "invalid request body",
	},
}

func New(key string) HttpError {
	return NewWithStatus(key, "", 0)
}

func NewWithMetadata(key, metadata string) HttpError {
	return NewWithStatus(key, metadata, 0)
}

func NewWithStatus(key, metadata string, status int) HttpError {
	if err, ok := httpErrors[key]; ok {
		err.ErrorCode = key
		err.Metadata = metadata
		if status != 0 {
			err.StatusCode = status
		}
		return err
	}
	return httpErrors[UndefinedErrorCode]
}

func NewWithDescription(description string, status int) HttpError {
	return HttpError{
		ErrorCode:   "JWT_ERROR",
		Description: description,
		StatusCode:  status,
	}
}
