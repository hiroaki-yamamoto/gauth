package middleware

import (
	"errors"

	"github.com/hiroaki-yamamoto/gauth/core"
)

// JWT to user converter

// FindUser represents a function to find a user by username,
type FindUser func(con interface{}, username string) (interface{}, error)

// JwtToUser converts jwStr to the corresponding user.
func JwtToUser(
	jwtStr string,
	findUserFunc FindUser,
	con interface{},
	config *core.Config,
) (interface{}, error) {
	token, err := core.ExtractToken(jwtStr, config)
	if err != nil {
		return nil, err
	}
	if len(token.ID) < 1 {
		return nil, errors.New("Not authenticated user")
	}
	user, err := findUserFunc(con, token.ID)
	if err != nil {
		return nil, err
	}
	return user, nil
}
