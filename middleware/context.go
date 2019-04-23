package middleware

// Auth package middleware

import (
	"context"
	"net/http"
)

import (
	"github.com/hiroaki-yamamoto/gauth/core"
)

type contextkey struct {
	name string
}

var userCtxKey = &contextkey{"user"}

// GetUser get user from context
func GetUser(ctx context.Context) interface{} {
	return ctx.Value(userCtxKey)
}

// HeaderMiddleware reads JWT from http header and
// puts the found user to the context.
func HeaderMiddleware(
	headerName string,
	con interface{},
	findUserFunc FindUser,
	config *core.Config,
) func(http.Handler) http.Handler {
	return headerMiddlewareBase(headerName, con, findUserFunc, config, false)
}

// CookieMiddleware reads JWT from cookie and
// puts the found user to the context.
func CookieMiddleware(
	cookieName string,
	con interface{},
	findUserFunc FindUser,
	config *core.Config,
) func(http.Handler) http.Handler {
	return cookieMiddlewareBase(cookieName, con, findUserFunc, config, false)
}
