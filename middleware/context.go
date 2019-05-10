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

// HeaderMiddleware reads JWT from http header and
// puts the found user to the context.
func HeaderMiddleware(
	con interface{},
	findUserFunc FindUser,
	config *_conf.Config,
) func(http.Handler) http.Handler {
	return headerMiddlewareBase(con, findUserFunc, config, false)
}

// CookieMiddleware reads JWT from cookie and
// puts the found user to the context.
func CookieMiddleware(
	con interface{},
	findUserFunc FindUser,
	config *_conf.Config,
) func(http.Handler) http.Handler {
	return cookieMiddlewareBase(con, findUserFunc, config, false)
}
