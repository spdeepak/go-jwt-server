package httperror

import (
	"fmt"
	"net/http"
)

type HttpError struct {
	ErrorCode   string `json:"errorCode,omitempty"`
	Description string `json:"description,omitempty"`
	Metadata    string `json:"metadata,omitempty"`
	StatusCode  int    `json:"-"`
}

func (e HttpError) Error() string {
	return fmt.Sprintf("errorCode: %s, description: %s,  metadata: %s", e.ErrorCode, e.Description, e.Metadata)
}

const (
	UndefinedErrorCode  = "JWT0000"
	Unauthorized        = "JWT0001"
	InvalidCredentials  = "JWT0002"
	InvalidRefreshToken = "JWT0003"
	TokenCreationFailed = "JWT0004"
	ExpiredBearerToken  = "JWT0005"
	BearerTokenMissing  = "JWT0006"
	ExpiredRefreshToken = "JWT0007"
)

var httpErrors = map[string]HttpError{
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
