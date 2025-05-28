package util

import (
	"regexp"
	"unicode"
)

func PasswordValidator(password string) bool {
	if len(password) < 8 {
		return false
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	specialChars := regexp.MustCompile(`[!@#$%&*]`)

	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		}
	}

	hasSpecial = specialChars.MatchString(password)

	return hasUpper && hasLower && hasDigit && hasSpecial
}
