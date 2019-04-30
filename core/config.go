package core

import (
	"time"

	"github.com/gbrlsnchs/jwt"
)

// Config is configuration model for ExtractToken
type Config struct {
	Signer                    jwt.Signer
	Audience, Issuer, Subject string
	ExpireIn                  time.Duration
}
