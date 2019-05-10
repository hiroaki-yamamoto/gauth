package middleware

import (
	"net/http"

	"github.com/hiroaki-yamamoto/gauth/config"
)

// Authentication required (or not) middleware

// LoginRequired enforces user authentication. If the user is not authenticated,
// it returns 401 (Not Authenticated).
func LoginRequired(
	con interface{},
	findUserFunc FindUser,
	conf *config.Config,
) func(http.Handler) http.Handler {
	return middlewareBase(con, findUserFunc, conf, true)
}
