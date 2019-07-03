package core_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hiroaki-yamamoto/gauth/clock"

	"github.com/gbrlsnchs/jwt/v2"
	"github.com/hiroaki-yamamoto/gauth/config"
	"github.com/hiroaki-yamamoto/gauth/core"
	"gotest.tools/assert"
)

// Login test

type User struct {
	Username string `json:"username,omitempty"`
}

func (me User) GetID() string {
	return me.Username
}

type TimeMock struct {
	Time time.Time
}

func (me TimeMock) Now() time.Time {
	return me.Time
}

func performLogin(conf *config.Config) (
	*httptest.ResponseRecorder, User, error,
) {
	rec := httptest.NewRecorder()
	user := User{Username: "test_username"}
	err := core.Login(rec, conf, user)
	return rec, user, err
}

func TestCookieLogin(t *testing.T) {
	clock.Clock = TimeMock{time.Unix(time.Now().Unix(), 0).UTC()}
	now := clock.Clock.Now()
	conf, err := config.New(
		"session", config.Cookie, jwt.NewHS256("test"),
		"Test Audience", "Test Issuer", "Test Subject",
		3600*time.Minute, config.CookieConfig{
			Path:     "/",
			Domain:   "localhost",
			Secure:   true,
			HTTPOnly: false,
			SameSite: http.SameSiteLaxMode,
		},
	)
	assert.NilError(t, err)
	rec, user, err := performLogin(conf)
	assert.NilError(t, err)
	var session *http.Cookie
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == conf.SessionName {
			session = cookie
			break
		}
	}
	assert.Assert(t, session != nil)

	assert.Equal(t, session.Path, conf.Path)
	assert.Equal(t, session.Domain, conf.Domain)
	assert.Equal(t, session.Secure, conf.Secure)
	assert.Equal(t, session.SameSite, conf.SameSite)

	assert.Equal(t, session.Expires, now.Add(conf.ExpireIn))
	assert.Equal(t, session.MaxAge, int(conf.ExpireIn/time.Second))

	parsedToken, err := core.ExtractToken(session.Value, conf)
	assert.NilError(t, err)
	assert.Equal(t, parsedToken.ID, user.Username)

	t.Run("Invalid token generation case", func(t *testing.T) {
		conf.Signer = jwt.NewHS256("")
		_, _, err := performLogin(conf)
		assert.Error(t, err, "jwt: HMAC key is empty")
	})
}

func TestHeaderLogin(t *testing.T) {
	clock.Clock = TimeMock{time.Unix(time.Now().Unix(), 0).UTC()}
	conf, err := config.New(
		"Auth", config.Header, jwt.NewHS256("test"),
		"Test Audience", "Test Issuer", "Test Subject",
		3600*time.Minute, config.CookieConfig{},
	)
	assert.NilError(t, err)
	rec, user, err := performLogin(conf)
	assert.NilError(t, err)
	session := rec.Header().Get("X-" + conf.SessionName)
	parsedToken, err := core.ExtractToken(session, conf)
	assert.NilError(t, err)
	assert.Equal(t, parsedToken.ID, user.Username)

	t.Run("Invalid token generation case", func(t *testing.T) {
		conf.Signer = jwt.NewHS256("")
		_, _, err := performLogin(conf)
		assert.Error(t, err, "jwt: HMAC key is empty")
	})
}
