package core_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hiroaki-yamamoto/gauth/clock"

	"github.com/gbrlsnchs/jwt"
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

func TestCookieLogin(t *testing.T) {
	clock.Clock = TimeMock{time.Unix(time.Now().Unix(), 0).UTC()}
	now := clock.Clock.Now()
	rec := httptest.NewRecorder()
	user := User{Username: "test_username"}
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
	core.Login(rec, conf, user)
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
}
