package tokens

import "github.com/golang-jwt/jwt/v5"

type TokenClaims struct {
	Name        string   `json:"name,omitempty"`
	Email       string   `json:"email" required:"true"`
	FirstName   string   `json:"first_name,omitempty"`
	LastName    string   `json:"last_name,omitempty"`
	Type        string   `json:"typ" required:"true"`
	AuthLevel   string   `json:"auth_level,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}
