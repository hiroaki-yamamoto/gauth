package middleware

// Auth package middleware

import (
	"context"
	"net/http"

	_conf "github.com/hiroaki-yamamoto/gauth/config"
)

type contextkey struct {
	name string
}

var userCtxKey = &contextkey{"user"}

// GetUser get user from context
func GetUser(ctx context.Context) interface{} {
	return ctx.Value(userCtxKey)
}

// SetUser set user to context
func SetUser(
	r *http.Request,
	user interface{},
) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, user))
}

// ContextMiddleware adds the authenticated user to http.Request.Context.
// if there's the token in the specified header / cookie in config.
func ContextMiddleware(
	con interface{},
	findUserFunc FindUser,
	config *_conf.Config,
) func(http.Handler) http.Handler {
	return middlewareBase(con, findUserFunc, config, false)
}
