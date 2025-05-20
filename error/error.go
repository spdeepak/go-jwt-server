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
	InvalidCredentials  = "JWT0001"
	InvalidRefreshToken = "JWT0002"
	TokenCreationFailed = "JWT0003"
)

var httpErrors = map[string]HttpError{
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
