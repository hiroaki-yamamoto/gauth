package core

import (
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt"
	"github.com/google/go-cmp/cmp"
	"gotest.tools/assert"
)

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
	config := Config{
		jwt.NewHS256("test secret key"),
		token.Audience,
		token.Issuer,
		token.Subject,
		2 * time.Hour,
	}
	// signer, token.Audience, token.Issuer, token.Subject,
	t.Run("For token", func(t *testing.T) {
		composedToken, err := ComposeToken(token, config.Signer)
		assert.NilError(t, err)
		extractedToken, err := ExtractToken(string(composedToken), &config)
		assert.NilError(t, err)
		assert.DeepEqual(
			t, *extractedToken, *token,
			cmp.AllowUnexported(*extractedToken, *token),
		)
	})
	t.Run("For id", func(t *testing.T) {
		composedToken, err := ComposeID(token.ID, &config)
		assert.NilError(t, err)
		extractedToken, err := ExtractToken(string(composedToken), &config)
		assert.NilError(t, err)
		assert.DeepEqual(
			t, *extractedToken, *token,
			cmp.AllowUnexported(*extractedToken, *token),
		)
	})
}

func TestNonParsableTokenTest(t *testing.T) {
	signer := jwt.NewHS256("test secret key")
	tok, err := ExtractToken("", &Config{signer, "", "", "", 2 * time.Hour})
	if err == nil {
		t.Fatal("extractToken must have an error: ", tok)
	}
}

func TestUnmashalFailure(t *testing.T) {
	signer := jwt.NewHS256("test secret key")
	tok := map[string]float64{"Test": 1.0, "exp": 123.456}
	payload, _ := jwt.Marshal(tok)
	txt, _ := signer.Sign(payload)
	exTok, err := ExtractToken(
		string(txt), &Config{signer, "", "", "", 2 * time.Hour},
	)
	if err == nil {
		t.Log(string(txt))
		t.Fatal("extractToken must have an error: ", exTok)
	}
}

func TestVerificationFailure(t *testing.T) {
	composeSigner := jwt.NewHS256("test secret key")
	extractSigner := jwt.NewHS256("really test secret key")
	tok := GetFixture()
	payload, _ := ComposeToken(tok, composeSigner)
	extracted, err := ExtractToken(
		string(payload), &Config{extractSigner, "", "", "", 2 * time.Hour},
	)
	if err == nil {
		t.Fatal("extractToken must have an error: ", extracted)
	}
}

func TestValidationFailure(t *testing.T) {
	signer := jwt.NewHS256("test secret key")
	extractAndCheck := func(payload []byte, tok *jwt.JWT, t *testing.T) {
		extracted, err := ExtractToken(
			string(payload),
			&Config{signer, tok.Audience, tok.Issuer, tok.Subject, 2 * time.Hour},
		)
		if err == nil {
			t.Fatal("extractToken must have an error: ", extracted)
		}
	}
	t.Run("Issued at is Future", func(t *testing.T) {
		tok := GetFixture()
		tok.IssuedAt = now.Add(5 * time.Hour).Unix()
		payload, _ := ComposeToken(tok, signer)
		extractAndCheck(payload, tok, t)
	})
	t.Run("Already Expired", func(t *testing.T) {
		tok := GetFixture()
		tok.ExpirationTime = now.Add(-5 * time.Hour).Unix()
		payload, _ := ComposeToken(tok, signer)
		extractAndCheck(payload, tok, t)
	})
	t.Run("Audience is not correct", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Audience = "Fake test audience"
		payload, _ := ComposeToken(tok1, signer)
		extractAndCheck(payload, tok2, t)
	})
	t.Run("Issuer is not correct", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Issuer = "Fake Test Issuer"
		payload, _ := ComposeToken(tok1, signer)
		extractAndCheck(payload, tok2, t)
	})
	t.Run("Subject is not correct", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Issuer = "Fake Test Issuer"
		payload, _ := ComposeToken(tok1, signer)
		extractAndCheck(payload, tok2, t)
	})
	t.Run("ID must not be validated", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.ID = "fakeTestID"
		payload, _ := ComposeToken(tok1, signer)
		_, err := ExtractToken(
			string(payload),
			&Config{signer, tok2.Audience, tok2.Issuer, tok2.Subject, 2 * time.Hour},
		)
		if err != nil {
			t.Fatal("extractToken must not have an error: ", err)
		}
	})
}
