package middleware

// Auth package middleware

import (
	"context"
	"errors"
	"log"
	"net/http"
)

import (
	"github.com/hiroaki-yamamoto/gauth/core"
)

// FindUser represents a function to find a user by username,
type FindUser func(con interface{}, username string) (interface{}, error)

type contextkey struct {
	name string
}

var userCtxKey = &contextkey{"user"}

func getUser(
	c string,
	findUserFunc FindUser,
	con interface{},
	config *core.Config,
) (interface{}, error) {
	token, err := core.ExtractToken(c, config)
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

// HeaderMiddleware reads JWT from http header and
// puts the found user to the context.
func HeaderMiddleware(
	headerName string,
	con interface{},
	findUserFunc FindUser,
	config *core.Config,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := r.Header.Get(headerName)
			user, err := getUser(c, findUserFunc, con, config)
			if err != nil {
				next.ServeHTTP(w, r)
				log.Print(err)
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, user)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

// CookieMiddleware reads JWT from cookie and
// puts the found user to the context.
func CookieMiddleware(
	cookieName string,
	con interface{},
	findUserFunc FindUser,
	config *core.Config,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(cookieName)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			user, err := getUser(c.Value, findUserFunc, con, config)
			if err != nil {
				next.ServeHTTP(w, r)
				log.Print(err)
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, user)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
