package config

import (
	"errors"
	"time"

	"github.com/gbrlsnchs/jwt"
)

// Config is configuration model for ExtractToken
type Config struct {
	Signer                    jwt.Signer
	Audience, Issuer, Subject string
	ExpireIn                  time.Duration
}

// New creates a new Config class safely.
// Note: If rxpireIn is 0, 3600 * time.Minute is used as a default-value.
func New(
	signer jwt.Signer,
	audience, issuer, subject string,
	expireIn time.Duration,
) (*Config, error) {
	if expireIn < 0 {
		return nil, errors.New(
			"expireIn must be 0-included positive time.Duration",
		)
	}
	if expireIn == 0 {
		expireIn = 3600 * time.Minute
	}
	return &Config{signer, audience, issuer, subject, expireIn}, nil
}
