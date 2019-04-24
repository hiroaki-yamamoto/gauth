package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/hiroaki-yamamoto/gauth/core"
)

// Error represents an error.
type Error struct {
	Message string `json:"message,omitempty"`
}

func processError(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
	err error,
	failOnError bool,
) {
	log.Print(err)
	if failOnError {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]Error{
			"errors": []Error{Error{"Not Authorized."}},
		})
		return
	}
	next.ServeHTTP(w, r)
}

func cookieMiddlewareBase(
	cookieName string,
	con interface{},
	findUserFunc FindUser,
	config *core.Config,
	failOnError bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(cookieName)
			if err != nil {
				processError(w, r, next, err, failOnError)
				return
			}
			user, err := JwtToUser(c.Value, findUserFunc, con, config)
			if err != nil {
				processError(w, r, next, err, failOnError)
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, user)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func headerMiddlewareBase(
	headerName string,
	con interface{},
	findUserFunc FindUser,
	config *core.Config,
	failOnError bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := r.Header.Get(headerName)
			user, err := JwtToUser(c, findUserFunc, con, config)
			if err != nil {
				processError(w, r, next, err, failOnError)
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, user)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}
