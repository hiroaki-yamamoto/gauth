package core

import "time"

import "github.com/gbrlsnchs/jwt"

func composeToken(
	username string,
	signer jwt.Signer,
	audience string,
	expiresAt time.Time,
	issuer string,
	subject string,
) ([]byte, error) {
	now := time.Now().UTC()
	jot := &jwt.JWT{
		Issuer:         issuer,
		Subject:        subject,
		Audience:       audience,
		ExpirationTime: expiresAt.Unix(),
		NotBefore:      now.Unix(),
		IssuedAt:       now.Unix(),
		ID:             username,
	}
	jot.SetAlgorithm(signer)
	payload, err := jwt.Marshal(jot)
	if err != nil {
		return nil, err
	}
	return signer.Sign(payload)
}

// extractToken extracts token string into verified JWT object.
func extractToken(
	token string,
	signer jwt.Signer,
	audience string,
	issuer string,
	subject string,
) (*jwt.JWT, error) {
	payload, sig, err := jwt.Parse(token)
	if err != nil {
		return nil, err
	}
	var jot jwt.JWT
	if err = jwt.Unmarshal(payload, &jot); err != nil {
		return nil, err
	}
	if err = signer.Verify(payload, sig); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	err = jot.Validate(
		jwt.IssuedAtValidator(now),
		jwt.ExpirationTimeValidator(now),
		jwt.AudienceValidator(audience),
		jwt.IssuerValidator(issuer),
		jwt.SubjectValidator(subject),
	)
	if err != nil {
		return nil, err
	}
	return &jot, nil
}
