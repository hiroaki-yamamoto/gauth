package middleware_test

import (
	"net/http"
	"testing"

	mid "github.com/hiroaki-yamamoto/gauth/middleware"
)

func TestHeaderLoginRequriedMiddleware(t *testing.T) {
	deployHeaderTest(
		t,
		mid.HeaderLoginRequired,
		http.StatusOK,
		http.StatusUnauthorized,
		[]mid.Error{
			mid.Error{Message: "Not Authorized."},
		},
	)
}

func TestCookieLoginRequiredMiddleware(t *testing.T) {
	deployCookieTest(
		t,
		mid.CookieLoginRequired,
		http.StatusOK,
		http.StatusUnauthorized,
		[]mid.Error{
			mid.Error{Message: "Not Authorized."},
		},
	)
}
