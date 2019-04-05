package core

import "reflect"
import "testing"
import "time"

import "github.com/gbrlsnchs/jwt"

var now = time.Now().UTC()

func GetFixture() *jwt.JWT {
	return &jwt.JWT{
		Issuer:         "test",
		Subject:        "test subject",
		Audience:       "test audience",
		ExpirationTime: now.Add(2 * time.Hour).Unix(),
		NotBefore:      now.Unix(),
		IssuedAt:       now.Unix(),
		ID:             "test username",
	}
}

func TestNormalTokenFunc(t *testing.T) {
	token := GetFixture()
	signer := jwt.NewHS256("test secret key")
	composedToken, err := ComposeToken(token, signer)
	if err != nil {
		t.Fatal(
			"composeToken must not return any errors, but it returned an error: ",
			err,
		)
	}
	extractedToken, err := ExtractToken(
		string(composedToken), signer, token.Audience, token.Issuer, token.Subject,
	)
	if err != nil {
		t.Fatal(
			"extractToken must not return any errors, but it returned an error: ",
			err,
		)
	}
	if !reflect.DeepEqual(*extractedToken, *token) {
		t.Log(*token)
		t.Log(*extractedToken)
		t.Fatal("The extracted token and token must be the same.")
	}
}
