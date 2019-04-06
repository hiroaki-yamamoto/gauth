package core

import "time"

import "github.com/gbrlsnchs/jwt"

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
	if err = signer.Verify(payload, sig); err != nil {
		return nil, err
	}
	if err = jwt.Unmarshal(payload, &jot); err != nil {
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
