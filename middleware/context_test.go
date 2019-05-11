package middleware_test

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

	"github.com/hiroaki-yamamoto/gauth/clock"
	"github.com/hiroaki-yamamoto/gauth/config"
	_conf "github.com/hiroaki-yamamoto/gauth/config"
	"github.com/hiroaki-yamamoto/gauth/core"
	mid "github.com/hiroaki-yamamoto/gauth/middleware"
)

type Middleware func(
	interface{},
	mid.FindUser,
	*config.Config,
) func(http.Handler) http.Handler

type TimeMock struct {
	Time time.Time
}

func (me TimeMock) Now() time.Time {
	return me.Time
}

type UserBase struct {
	Username string      `json:"username,omitempty"`
	Errors   []mid.Error `json:"errors,omitempty"`
}

type User struct {
	UserBase
}

func (me User) GetID() string {
	return me.UserBase.Username
}

type Con struct{}

var handlerFunc = http.HandlerFunc(func(
	w http.ResponseWriter,
	r *http.Request,
) {
	user := mid.GetUser(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
})

func cookieTest(
	username string,
	cookieName string,
	conf *_conf.Config,
	code int,
	user interface{},
	expdiff time.Duration,
	srvHandler *http.Handler,
	autoExtend bool,
) func(t *testing.T) {
	clock.Clock = TimeMock{time.Unix(time.Now().Unix(), 0).UTC()}
	now := clock.Clock.Now()
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
			Name:  cookieName,
			Value: string(token),
		})
		(*srvHandler).ServeHTTP(rec, req)

		var session *http.Cookie
		for _, cookie := range rec.Result().Cookies() {
			if cookie.Name == conf.SessionName {
				session = cookie
				break
			}
		}

		if autoExtend && session != nil {
			assert.Equal(t, session.Path, conf.Path)
			assert.Equal(t, session.Domain, conf.Domain)
			assert.Equal(t, session.Expires, now.Add(conf.ExpireIn))
			assert.Equal(t, session.MaxAge, int(conf.ExpireIn/time.Second))
			assert.Equal(t, session.Secure, conf.Secure)
			assert.Equal(t, session.HttpOnly, conf.HTTPOnly)
			assert.Equal(t, session.SameSite, conf.SameSite)

			tok, err := core.ExtractToken(session.Value, conf)
			assert.NilError(t, err)
			assert.Equal(
				t,
				time.Unix(tok.ExpirationTime, 0).UTC(),
				clock.Clock.Now().Add(3600*time.Hour),
			)
		} else {
			assert.Assert(t, session == nil)
		}

		resUser := UserBase{}
		err = json.NewDecoder(rec.Body).Decode(&resUser)
		assert.NilError(t, err)
		assert.Equal(t, rec.Code, code)

		expUser, ok := user.(User)
		if ok {
			assert.Equal(t, resUser.Username, expUser.UserBase.Username)
			assert.DeepEqual(t, resUser.Errors, expUser.UserBase.Errors)
		} else {
			expUser := user.(UserBase)
			assert.DeepEqual(t, resUser, expUser)
		}
	}
}

func headerTest(
	username string,
	headerName string,
	conf *_conf.Config,
	code int,
	user interface{},
	expdiff time.Duration,
	srvHandler *http.Handler,
	autoExtend bool,
) func(t *testing.T) {
	clock.Clock = TimeMock{time.Unix(time.Now().Unix(), 0).UTC()}
	now := clock.Clock.Now()
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
		req.Header.Add(headerName, string(token))
		(*srvHandler).ServeHTTP(rec, req)

		resUser := UserBase{}
		err = json.NewDecoder(rec.Body).Decode(&resUser)
		assert.NilError(t, err)
		assert.Equal(t, rec.Code, code)
		expUser, ok := user.(User)
		if ok {
			assert.Equal(t, resUser.Username, expUser.UserBase.Username)
			assert.DeepEqual(t, resUser.Errors, expUser.UserBase.Errors)
		} else {
			expUser := user.(UserBase)
			assert.DeepEqual(t, resUser, expUser)
		}

		hdrTokStr := rec.Header().Get("X-" + conf.SessionName)
		if autoExtend {
			hdrTok, err := core.ExtractToken(hdrTokStr, conf)
			assert.NilError(t, err)
			assert.Equal(
				t,
				time.Unix(hdrTok.ExpirationTime, 0).UTC(),
				clock.Clock.Now().Add(3600*time.Hour),
			)
			return
		}
		assert.Assert(t, hdrTokStr == "")
	}
}

func deployHeaderTest(
	t *testing.T,
	middleware Middleware,
	okCode int,
	wrongCode int,
	wrongMsgs []mid.Error,
) {
	con := &Con{}
	cookieConf := _conf.CookieConfig{
		Path:     "/",
		Domain:   "localhost",
		Secure:   false,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	conf, err := _conf.New(
		"Authorization",
		_conf.Header,
		jwt.NewHS256("test"),
		"Test Audience",
		"Test Issuer",
		"Test Subject",
		3600*time.Hour,
		cookieConf,
	)
	assert.NilError(t, err)
	handler := middleware(
		con, func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return User{UserBase{username, []mid.Error{}}}, nil
		}, conf,
	)(handlerFunc)
	errorHandler := middleware(
		con, func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return nil, errors.New("Error Test")
		}, conf,
	)(handlerFunc)
	customUserHandler := middleware(
		con, func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return UserBase{username, []mid.Error{}}, nil
		}, conf,
	)(handlerFunc)

	t.Run(
		"There's token in the header",
		headerTest(
			"test_username", conf.SessionName, conf, okCode,
			User{UserBase{"test_username", []mid.Error(nil)}},
			2*time.Hour, &handler, true,
		),
	)
	t.Run(
		"There's token in the **different** header",
		headerTest(
			"test_username", conf.SessionName+"-Something", conf,
			wrongCode, User{UserBase{Errors: wrongMsgs}},
			2*time.Hour, &handler, false,
		),
	)
	t.Run(
		"Empty ID in the header",
		headerTest(
			"", conf.SessionName, conf, wrongCode,
			User{UserBase{Errors: wrongMsgs}}, 2*time.Hour, &handler, false,
		),
	)
	t.Run(
		"There's expired token in the header",
		headerTest(
			"test_username", conf.SessionName, conf, wrongCode,
			User{UserBase{Errors: wrongMsgs}}, -2*time.Hour, &handler, false,
		),
	)
	t.Run(
		"The user is CustomUser",
		headerTest(
			"test_username", conf.SessionName, conf,
			okCode, UserBase{"test_username", []mid.Error(nil)},
			2*time.Hour, &customUserHandler, false,
		),
	)
	t.Run(
		"findUserFunc returns an error",
		headerTest(
			"test_username", conf.SessionName, conf, wrongCode,
			User{UserBase{Errors: wrongMsgs}}, 2*time.Hour, &errorHandler, false,
		),
	)
	t.Run(
		"There's token in cookie, but header middleware shouldn't recognize it.",
		cookieTest(
			"test_username", conf.SessionName, conf, wrongCode,
			User{UserBase{Errors: wrongMsgs}}, 2*time.Hour,
			&handler, false,
		),
	)
}

func deployCookieTest(
	t *testing.T,
	middleware Middleware,
	okCode int,
	wrongCode int,
	wrongMsgs []mid.Error,
) {
	con := &Con{}
	cookieConf := _conf.CookieConfig{
		Path:     "/",
		Domain:   "localhost",
		Secure:   false,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	conf, err := _conf.New(
		"session",
		_conf.Cookie,
		jwt.NewHS256("test"),
		"Test Audience",
		"Test Issuer",
		"Test Subject",
		3600*time.Hour,
		cookieConf,
	)
	assert.NilError(t, err)
	handler := middleware(
		con, func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return User{UserBase{username, []mid.Error{}}}, nil
		}, conf,
	)(handlerFunc)
	errorHandler := middleware(
		con, func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return nil, errors.New("Error Test")
		}, conf,
	)(handlerFunc)
	customUserHandler := middleware(
		con, func(fcon interface{}, username string) (interface{}, error) {
			assert.Equal(t, con, fcon)
			return UserBase{username, []mid.Error{}}, nil
		}, conf,
	)(handlerFunc)

	t.Run(
		"There's token in the cookie",
		cookieTest(
			"test_username", conf.SessionName, conf,
			okCode, User{UserBase{"test_username", []mid.Error(nil)}},
			2*time.Hour, &handler, true,
		),
	)
	t.Run(
		"There's token in the **different** cookie",
		cookieTest(
			"test_username", conf.SessionName+"-something", conf,
			wrongCode, User{UserBase{Errors: wrongMsgs}},
			2*time.Hour, &handler, false,
		),
	)
	t.Run(
		"Empty ID in the cookie",
		cookieTest(
			"", conf.SessionName, conf,
			wrongCode, User{UserBase{Errors: wrongMsgs}},
			2*time.Hour, &handler, false,
		),
	)
	t.Run(
		"There's expired token in the cookie",
		cookieTest(
			"test_username", conf.SessionName, conf,
			wrongCode, User{UserBase{Errors: wrongMsgs}},
			-2*time.Hour, &handler, false,
		),
	)
	t.Run(
		"findUserFunc returns an error",
		cookieTest(
			"test_username", conf.SessionName, conf,
			wrongCode, User{UserBase{Errors: wrongMsgs}},
			2*time.Hour, &errorHandler, false,
		),
	)
	t.Run(
		"The user is CustomUser",
		cookieTest(
			"test_username", conf.SessionName, conf,
			okCode, UserBase{"test_username", []mid.Error(nil)},
			2*time.Hour, &customUserHandler, false,
		),
	)
	t.Run(
		"There's token in the header, but cookie middleware shouldn't recognize it.",
		headerTest(
			"test_username", conf.SessionName, conf,
			wrongCode, User{UserBase{Errors: wrongMsgs}},
			2*time.Hour, &handler, false,
		),
	)
}

func TestHeaderMiddleware(t *testing.T) {
	deployHeaderTest(
		t,
		mid.ContextMiddleware,
		http.StatusOK,
		http.StatusOK,
		[]mid.Error(nil),
	)
}

func TestCookieHandlerMiddleware(t *testing.T) {
	deployCookieTest(
		t,
		mid.ContextMiddleware,
		http.StatusOK,
		http.StatusOK,
		[]mid.Error(nil),
	)
}
