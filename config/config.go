package config

import (
	"errors"
	"net/http"
	"time"

	"github.com/gbrlsnchs/jwt/v2"
)

// MiddlewareType indicates the type of middleware to be used.
type MiddlewareType int

const (
	// Cookie specifies cookie as the type of middleware.
	Cookie MiddlewareType = iota
	// Header specifies header as the type of middleware.
	Header
)

// Config is configuration model for ExtractToken
type Config struct {
	CookieConfig
	// The name of the session. This is used as the name of the header when
	// HeaderMiddleware / HeaderLoginRequired is used, and as the name of the
	// cookie when CookieMiddleware / CookieLoginRequired is used.
	SessionName               string
	MiddlewareType            MiddlewareType
	Signer                    jwt.Signer
	Audience, Issuer, Subject string
	ExpireIn                  time.Duration
}

// CookieConfig is used by Login function in the case of using cookie
// for session management.
type CookieConfig struct {
	Path, Domain string
	Secure       bool // <- Set true when using https.
	HTTPOnly     bool // <- Set false/zero-value when using with XHR.
	SameSite     http.SameSite
}

// New creates a new Config class safely.
// Note: If rxpireIn is 0, 3600 * time.Minute is used as a default-value.
func New(
	// Refer the comment of Config.SessionName.
	sessionName string,
	middlewareType MiddlewareType,
	signer jwt.Signer,
	audience, issuer, subject string,
	expireIn time.Duration,
	cookieConf CookieConfig,
) (*Config, error) {
	if expireIn < 0 {
		return nil, errors.New(
			"expireIn must be 0-included positive time.Duration",
		)
	}
	if expireIn == 0 {
		expireIn = 3600 * time.Minute
	}
	return &Config{
		cookieConf, sessionName,
		middlewareType, signer,
		audience, issuer,
		subject, expireIn,
	}, nil
}
