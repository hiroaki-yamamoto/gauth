package core

import (
	"time"

	"github.com/gbrlsnchs/jwt"
)

// ComposeToken generates JWT token string from specified paramenters.
func ComposeToken(model *jwt.JWT, signer jwt.Signer) ([]byte, error) {
	payload, _ := jwt.Marshal(model)
	// In jwt.JWT case, no errors seem to be returned for now.
	// if err != nil {
	// 	return nil, err
	// }
	return signer.Sign(payload)
}

// ExtractToken extracts token string into verified JWT object.
func ExtractToken(
	token string,
	config *Config,
) (*jwt.JWT, error) {
	now := time.Now().UTC()
	payload, sig, err := jwt.Parse(token)
	if err != nil {
		return nil, err
	}
	var jot jwt.JWT
	if err = config.Signer.Verify(payload, sig); err != nil {
		return nil, err
	}
	if err = jwt.Unmarshal(payload, &jot); err != nil {
		return nil, err
	}
	err = jot.Validate(
		jwt.IssuedAtValidator(now),
		jwt.ExpirationTimeValidator(now),
		jwt.AudienceValidator(config.Audience),
		jwt.IssuerValidator(config.Issuer),
		jwt.SubjectValidator(config.Subject),
	)
	if err != nil {
		return nil, err
	}
	return &jot, nil
}
