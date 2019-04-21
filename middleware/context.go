package middleware

// Auth package middleware

import (
	"context"
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
			token, err := core.ExtractToken(c, config)
			if err != nil {
				next.ServeHTTP(w, r)
				log.Print(err)
				return
			}
			if len(token.ID) < 1 {
				next.ServeHTTP(w, r)
				log.Print("Not authenticated user")
				return
			}
			user, err := findUserFunc(con, token.ID)
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
