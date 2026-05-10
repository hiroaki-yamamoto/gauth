package core

import (
	"errors"
	"time"

	"codeberg.org/gbrlsnchs/jwt"
	"github.com/hiroaki-yamamoto/gauth/config"
)

// ComposeToken generates JWT token string from specified paramenters.
func ComposeToken(model *jwt.JWT[jwt.None], signer jwt.Signer) ([]byte, error) {
	return jwt.Sign(model, signer)
}

// ComposeID generates JWT token string with specified ID
// (that is generally used as an username) and Config.
func ComposeID(ID string, config *config.Config) ([]byte, error) {
	now := time.Now()
	var aud jwt.Audience
	if config.Audience != "" {
		aud = jwt.Audience{config.Audience}
	}
	jot := &jwt.JWT[jwt.None]{
		Claims: jwt.Claims[jwt.None]{
			Issuer:     config.Issuer,
			Subject:    config.Subject,
			Audience:   aud,
			Expiration: jwt.ConvertTime(now.Add(config.ExpireIn)),
			NotBefore:  jwt.ConvertTime(now),
			IssuedAt:   jwt.ConvertTime(now),
			JWTID:      ID,
		},
	}
	return ComposeToken(jot, config.Signer)
}

// ExtractToken extracts token string into verified JWT object.
func ExtractToken(
	token string,
	config *config.Config,
) (*jwt.JWT[jwt.None], error) {
	now := time.Now().UTC()
	t, err := jwt.Parse([]byte(token))
	if err != nil {
		return nil, err
	}

	verifier, ok := config.Signer.(jwt.Verifier)
	if !ok {
		return nil, errors.New("Signer does not implement jwt.Verifier")
	}

	if err = jwt.Verify(t, verifier); err != nil {
		return nil, err
	}

	jot, err := jwt.Decode[jwt.None](t)
	if err != nil {
		return nil, err
	}

	if jot.IsExpired(now) {
		return nil, errors.New("jwt is expired")
	}
	if !jot.IsActive(now) {
		return nil, errors.New("jwt is not active yet")
	}
	if time.Unix(int64(jot.Claims.IssuedAt), 0).After(now) {
		return nil, errors.New("jwt used before issued")
	}
	if config.Audience != "" && !jot.InScope(config.Audience) {
		return nil, errors.New("invalid audience")
	}
	if config.Issuer != "" && jot.Claims.Issuer != config.Issuer {
		return nil, errors.New("invalid issuer")
	}
	if config.Subject != "" && jot.Claims.Subject != config.Subject {
		return nil, errors.New("invalid subject")
	}

	return jot, nil
}
