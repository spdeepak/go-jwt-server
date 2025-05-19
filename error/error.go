package httperror

import "fmt"

type HttpError struct {
	ErrorCode   string `json:"errorCode"`
	Description string `json:"description"`
	Metadata    string `json:"metadata"`
	StatusCode  int    `json:"-"`
}

func (e HttpError) Error() string {
	return fmt.Sprintf("errorCode: %s, description: %s,  metadata: %s", e.ErrorCode, e.Description, e.Metadata)
}
