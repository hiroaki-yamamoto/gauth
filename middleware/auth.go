package middleware

import (
	"net/http"

	"github.com/hiroaki-yamamoto/gauth/core"
)

// Authentication required (or not) middleware

// HeaderLoginRequired enforces jwt-login authentication at
// the specified header.
//
// Note that this middleware calls HeaderMiddleware implicitly.
func HeaderLoginRequired(
	headerName string,
	con interface{},
	findUserFunc FindUser,
	config *core.Config,
) func(http.Handler) http.Handler {
	return headerMiddlewareBase(headerName, con, findUserFunc, config, true)
}

// CookieLoginRequired enforces jwt-login authentication at
// the specified cookie.
//
// Note that this middleware calls CookieMiddleware implicitly.
func CookieLoginRequired(
	cookieName string,
	con interface{},
	findUserFunc FindUser,
	config *core.Config,
) func(http.Handler) http.Handler {
	return cookieMiddlewareBase(cookieName, con, findUserFunc, config, true)
}
