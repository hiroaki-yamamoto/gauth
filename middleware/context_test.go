package middleware

// Context test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt"
	"gotest.tools/assert"

	"github.com/hiroaki-yamamoto/gauth/core"
)

type User struct {
	Username string  `json:"username,omitempty"`
	Errors   []Error `json:"errors,omitempty"`
}

type Con struct{}

var handlerFunc = http.HandlerFunc(func(
	w http.ResponseWriter,
	r *http.Request,
) {
	user := GetUser(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
})

func cookieTest(
	username string,
	cookiename string,
	conf *core.Config,
	code int,
	user User,
	expdiff time.Duration,
	srvHandler *http.Handler,
) func(t *testing.T) {
	now := time.Now().UTC()
	return func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		token, err := core.ComposeToken(&jwt.JWT{
			Issuer:         conf.Issuer,
			Subject:        conf.Subject,
			Audience:       conf.Audience,
			ExpirationTime: now.Add(expdiff).Unix(),
			NotBefore:      now.Unix(),
			IssuedAt:       now.Unix(),
			ID:             username,
		}, conf.Signer)
		assert.NilError(t, err)
		req.AddCookie(&http.Cookie{
			Name:  cookiename,
			Value: string(token),
		})
		(*srvHandler).ServeHTTP(rec, req)
		resUser := User{}
		err = json.NewDecoder(rec.Body).Decode(&resUser)
		assert.NilError(t, err)
		assert.Equal(t, rec.Code, code)
		assert.DeepEqual(t, resUser, user)
	}
}

func headerTest(
	username string,
	conf *core.Config,
	code int,
	user User,
	expdiff time.Duration,
	srvHandler *http.Handler,
) func(t *testing.T) {
	now := time.Now().UTC()
	return func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		token, err := core.ComposeToken(&jwt.JWT{
			Issuer:         conf.Issuer,
			Subject:        conf.Subject,
			Audience:       conf.Audience,
			ExpirationTime: now.Add(expdiff).Unix(),
			NotBefore:      now.Unix(),
			IssuedAt:       now.Unix(),
			ID:             username,
		}, conf.Signer)
		assert.NilError(t, err)
		req.Header.Add("Authorization", string(token))
		(*srvHandler).ServeHTTP(rec, req)
		resUser := User{}
		err = json.NewDecoder(rec.Body).Decode(&resUser)
		assert.NilError(t, err)
		assert.Equal(t, rec.Code, code)
		assert.DeepEqual(t, resUser, user)
	}
}

func TestHeaderMiddleware(t *testing.T) {
	con := &Con{}
	conf := core.Config{
		Signer:   jwt.NewHS256("test"),
		Audience: "Test Audience",
		Issuer:   "Test Issuer",
		Subject:  "Test Subject",
	}
	handler := HeaderMiddleware(
		"Authorization", con,
		func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return User{username, []Error{}}, nil
		}, &conf,
	)(handlerFunc)
	errorHandler := HeaderMiddleware(
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
			"", &conf, http.StatusOK,
			User{}, 2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"There's expired token in the header",
		headerTest(
			"test_username", &conf, http.StatusOK,
			User{}, -2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"findUserFunc returns an error",
		headerTest(
			"test_username", &conf, http.StatusOK,
			User{}, 2*time.Hour,
			&errorHandler,
		),
	)
	t.Run(
		"There's token in cookie, but header middleware shouldn't recognize it.",
		cookieTest(
			"test_username", "session", &conf, http.StatusOK,
			User{}, 2*time.Hour,
			&handler,
		),
	)
}

func TestCookieHandlerMiddleware(t *testing.T) {
	con := &Con{}
	conf := core.Config{
		Signer:   jwt.NewHS256("test"),
		Audience: "Test Audience",
		Issuer:   "Test Issuer",
		Subject:  "Test Subject",
	}
	handler := CookieMiddleware(
		"session", con,
		func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return User{username, []Error{}}, nil
		}, &conf,
	)(handlerFunc)
	errorHandler := CookieMiddleware(
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
			http.StatusOK, User{},
			2*time.Hour, &handler,
		),
	)
	t.Run(
		"Empty ID in the cookie",
		cookieTest(
			"", "session", &conf,
			http.StatusOK,
			User{}, 2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"There's expired token in the cookie",
		cookieTest(
			"test_username", "session", &conf,
			http.StatusOK,
			User{}, -2*time.Hour,
			&handler,
		),
	)
	t.Run(
		"findUserFunc returns an error",
		cookieTest(
			"test_username", "session", &conf,
			http.StatusOK,
			User{}, 2*time.Hour,
			&errorHandler,
		),
	)
	t.Run(
		"There's token in the header, but cookie middleware shouldn't recognize it.",
		headerTest(
			"test_username", &conf,
			http.StatusOK,
			User{}, 2*time.Hour,
			&handler,
		),
	)
}