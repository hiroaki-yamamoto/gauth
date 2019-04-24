package middleware

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt"
	"github.com/hiroaki-yamamoto/gauth/core"
	"gotest.tools/assert"
)

func TestHeaderLoginRequriedMiddleware(t *testing.T) {
	con := &Con{}
	conf := core.Config{
		Signer:   jwt.NewHS256("test"),
		Audience: "Test Audience",
		Issuer:   "Test Issuer",
		Subject:  "Test Subject",
	}
	handler := HeaderLoginRequired(
		"Authorization", con,
		func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return User{username, []Error{}}, nil
		}, &conf,
	)(handlerFunc)
	errorHandler := HeaderLoginRequired(
		"Authorization", con,
		func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return nil, errors.New("Error Test")
		}, &conf,
	)(handlerFunc)

	t.Run(
		"There's token in the header",
		headerTest(
			"test_username", &conf, http.StatusOK,
			User{"test_username", []Error(nil)}, 2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"Empty ID in the header",
		headerTest(
			"", &conf, http.StatusUnauthorized,
			User{Errors: []Error{Error{"Not Authorized."}}}, 2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"There's expired token in the header",
		headerTest(
			"test_username", &conf, http.StatusUnauthorized,
			User{Errors: []Error{Error{"Not Authorized."}}}, -2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"findUserFunc returns an error",
		headerTest(
			"test_username", &conf, http.StatusUnauthorized,
			User{Errors: []Error{Error{"Not Authorized."}}}, 2*time.Hour,
			&errorHandler,
		),
	)
	t.Run(
		"There's token in cookie, but header middleware shouldn't recognize it.",
		cookieTest(
			"test_username", "session", &conf, http.StatusUnauthorized,
			User{Errors: []Error{Error{"Not Authorized."}}}, 2*time.Hour,
			&handler,
		),
	)
}

func TestCookieLoginRequiredMiddleware(t *testing.T) {
	con := &Con{}
	conf := core.Config{
		Signer:   jwt.NewHS256("test"),
		Audience: "Test Audience",
		Issuer:   "Test Issuer",
		Subject:  "Test Subject",
	}
	handler := CookieLoginRequired(
		"session", con,
		func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return User{username, []Error{}}, nil
		}, &conf,
	)(handlerFunc)
	errorHandler := CookieLoginRequired(
		"session", con,
		func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return nil, errors.New("Error Test")
		}, &conf,
	)(handlerFunc)

	t.Run(
		"There's token in the cookie",
		cookieTest(
			"test_username", "session", &conf,
			http.StatusOK, User{"test_username", []Error(nil)},
			2*time.Hour, &handler,
		),
	)
	t.Run(
		"There's token in the **different** cookie",
		cookieTest(
			"test_username", "auth", &conf,
			http.StatusUnauthorized, User{Errors: []Error{Error{"Not Authorized."}}},
			2*time.Hour, &handler,
		),
	)
	t.Run(
		"Empty ID in the cookie",
		cookieTest(
			"", "session", &conf,
			http.StatusUnauthorized,
			User{Errors: []Error{Error{"Not Authorized."}}}, 2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"There's expired token in the cookie",
		cookieTest(
			"test_username", "session", &conf,
			http.StatusUnauthorized,
			User{Errors: []Error{Error{"Not Authorized."}}}, -2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"findUserFunc returns an error",
		cookieTest(
			"test_username", "session", &conf,
			http.StatusUnauthorized,
			User{Errors: []Error{Error{"Not Authorized."}}}, 2*time.Hour,
			&errorHandler,
		),
	)
	t.Run(
		"There's token in the header, but cookie middleware shouldn't recognize it.",
		headerTest(
			"test_username", &conf,
			http.StatusUnauthorized,
			User{Errors: []Error{Error{"Not Authorized."}}}, 2*time.Hour,
			&handler,
		),
	)
}
