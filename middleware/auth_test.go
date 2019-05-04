package middleware_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt"
	_conf "github.com/hiroaki-yamamoto/gauth/config"
	mid "github.com/hiroaki-yamamoto/gauth/middleware"
	"gotest.tools/assert"
)

func TestHeaderLoginRequriedMiddleware(t *testing.T) {
	con := &Con{}
	conf := _conf.Config{
		Signer:   jwt.NewHS256("test"),
		Audience: "Test Audience",
		Issuer:   "Test Issuer",
		Subject:  "Test Subject",
	}
	handler := mid.HeaderLoginRequired(
		"Authorization", con,
		func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return User{UserBase{username, []mid.Error{}}}, nil
		}, &conf,
	)(handlerFunc)
	errorHandler := mid.HeaderLoginRequired(
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
			User{UserBase{"test_username", []mid.Error(nil)}}, 2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"Empty ID in the header",
		headerTest(
			"", &conf, http.StatusUnauthorized,
			User{UserBase{Errors: []mid.Error{mid.Error{"Not Authorized."}}}},
			2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"There's expired token in the header",
		headerTest(
			"test_username", &conf, http.StatusUnauthorized,
			User{UserBase{Errors: []mid.Error{mid.Error{"Not Authorized."}}}},
			-2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"findUserFunc returns an error",
		headerTest(
			"test_username", &conf, http.StatusUnauthorized,
			User{UserBase{Errors: []mid.Error{mid.Error{"Not Authorized."}}}},
			2*time.Hour,
			&errorHandler,
		),
	)
	t.Run(
		"There's token in cookie, but header middleware shouldn't recognize it.",
		cookieTest(
			"test_username", "session", &conf, http.StatusUnauthorized,
			User{UserBase{Errors: []mid.Error{mid.Error{"Not Authorized."}}}},
			2*time.Hour,
			&handler, false,
		),
	)
}

func TestCookieLoginRequiredMiddleware(t *testing.T) {
	con := &Con{}
	conf := _conf.Config{
		Signer:   jwt.NewHS256("test"),
		Audience: "Test Audience",
		Issuer:   "Test Issuer",
		Subject:  "Test Subject",
		ExpireIn: 3600 * time.Hour,
	}
	handler := mid.CookieLoginRequired(
		"session", con,
		func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return User{UserBase{username, []mid.Error{}}}, nil
		}, &conf,
	)(handlerFunc)
	errorHandler := mid.CookieLoginRequired(
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
			http.StatusOK,
			User{UserBase{"test_username", []mid.Error(nil)}},
			2*time.Hour, &handler, true,
		),
	)
	t.Run(
		"There's token in the **different** cookie",
		cookieTest(
			"test_username", "auth", &conf,
			http.StatusUnauthorized,
			User{UserBase{Errors: []mid.Error{mid.Error{"Not Authorized."}}}},
			2*time.Hour, &handler, false,
		),
	)
	t.Run(
		"Empty ID in the cookie",
		cookieTest(
			"", "session", &conf,
			http.StatusUnauthorized,
			User{UserBase{Errors: []mid.Error{mid.Error{"Not Authorized."}}}},
			2*time.Hour, &handler, false,
		),
	)
	t.Run(
		"There's expired token in the cookie",
		cookieTest(
			"test_username", "session", &conf,
			http.StatusUnauthorized,
			User{UserBase{Errors: []mid.Error{mid.Error{"Not Authorized."}}}},
			-2*time.Hour, &handler, false,
		),
	)
	t.Run(
		"findUserFunc returns an error",
		cookieTest(
			"test_username", "session", &conf,
			http.StatusUnauthorized,
			User{UserBase{Errors: []mid.Error{mid.Error{"Not Authorized."}}}},
			2*time.Hour, &errorHandler, false,
		),
	)
	t.Run(
		"There's token in the header, but cookie middleware shouldn't recognize it.",
		headerTest(
			"test_username", &conf,
			http.StatusUnauthorized,
			User{UserBase{Errors: []mid.Error{mid.Error{"Not Authorized."}}}},
			2*time.Hour, &handler,
		),
	)
}
