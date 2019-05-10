package middleware

import (
	"net/http"

	"github.com/hiroaki-yamamoto/gauth/config"
)

// Authentication required (or not) middleware

// HeaderLoginRequired enforces jwt-login authentication at
// the specified header.
//
// Note that this middleware calls HeaderMiddleware implicitly.
func HeaderLoginRequired(
	con interface{},
	findUserFunc FindUser,
	config *config.Config,
) func(http.Handler) http.Handler {
	return headerMiddlewareBase(con, findUserFunc, config, true)
}

// CookieLoginRequired enforces jwt-login authentication at
// the specified cookie.
//
// Note that this middleware calls CookieMiddleware implicitly.
func CookieLoginRequired(
	con interface{},
	findUserFunc FindUser,
	config *config.Config,
) func(http.Handler) http.Handler {
	return cookieMiddlewareBase(con, findUserFunc, config, true)
}
