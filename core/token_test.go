package core_test

import (
	"testing"
	"time"

	"github.com/gbrlsnchs/jwt/v2"
	"github.com/google/go-cmp/cmp"
	_conf "github.com/hiroaki-yamamoto/gauth/config"
	"github.com/hiroaki-yamamoto/gauth/core"
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
	config := _conf.Config{
		Signer:   jwt.NewHS256("test secret key"),
		Audience: token.Audience,
		Issuer:   token.Issuer,
		Subject:  token.Subject,
		ExpireIn: 2 * time.Hour,
	}
	// signer, token.Audience, token.Issuer, token.Subject,
	t.Run("For token", func(t *testing.T) {
		composedToken, err := core.ComposeToken(token, config.Signer)
		assert.NilError(t, err)
		extractedToken, err := core.ExtractToken(string(composedToken), &config)
		assert.NilError(t, err)
		assert.DeepEqual(
			t, *extractedToken, *token,
			cmp.AllowUnexported(*extractedToken, *token),
		)
	})
	t.Run("For id", func(t *testing.T) {
		composedToken, err := core.ComposeID(token.ID, &config)
		assert.NilError(t, err)
		extractedToken, err := core.ExtractToken(string(composedToken), &config)
		assert.NilError(t, err)
		assert.DeepEqual(
			t, *extractedToken, *token,
			cmp.AllowUnexported(*extractedToken, *token),
		)
	})
}

func TestNonParsableTokenTest(t *testing.T) {
	signer := jwt.NewHS256("test secret key")
	tok, err := core.ExtractToken("", &_conf.Config{
		Signer:   signer,
		Audience: "",
		Issuer:   "",
		Subject:  "",
		ExpireIn: 2 * time.Hour,
	})
	assert.ErrorContains(t, err, "jwt:")
	assert.Assert(t, tok == nil, tok)
}

func TestUnmashalFailure(t *testing.T) {
	signer := jwt.NewHS256("test secret key")
	tok := map[string]float64{"Test": 1.0, "exp": 123.456}
	payload, _ := jwt.Marshal(tok)
	txt, _ := signer.Sign(payload)
	exTok, err := core.ExtractToken(
		string(txt), &_conf.Config{
			Signer:   signer,
			Audience: "",
			Issuer:   "",
			Subject:  "",
			ExpireIn: 2 * time.Hour,
		},
	)
	assert.ErrorContains(t, err, "json:", string(txt))
	assert.Assert(t, exTok == nil, exTok)
}

func TestVerificationFailure(t *testing.T) {
	composeSigner := jwt.NewHS256("test secret key")
	extractSigner := jwt.NewHS256("really test secret key")
	tok := GetFixture()
	payload, _ := core.ComposeToken(tok, composeSigner)
	extracted, err := core.ExtractToken(
		string(payload), &_conf.Config{
			Signer:   extractSigner,
			Audience: "",
			Issuer:   "",
			Subject:  "",
			ExpireIn: 2 * time.Hour,
		},
	)
	if err == nil {
		t.Fatal("extractToken must have an error: ", extracted)
	}
}

func TestValidationFailure(t *testing.T) {
	signer := jwt.NewHS256("test secret key")
	extractAndCheck := func(payload []byte, tok *jwt.JWT, t *testing.T) {
		extracted, err := core.ExtractToken(
			string(payload),
			&_conf.Config{
				Signer:   signer,
				Audience: tok.Audience,
				Issuer:   tok.Issuer,
				Subject:  tok.Subject,
				ExpireIn: 2 * time.Hour,
			},
		)
		if err == nil {
			t.Fatal("extractToken must have an error: ", extracted)
		}
	}
	t.Run("Issued at is Future", func(t *testing.T) {
		tok := GetFixture()
		tok.IssuedAt = now.Add(5 * time.Hour).Unix()
		payload, _ := core.ComposeToken(tok, signer)
		extractAndCheck(payload, tok, t)
	})
	t.Run("Already Expired", func(t *testing.T) {
		tok := GetFixture()
		tok.ExpirationTime = now.Add(-5 * time.Hour).Unix()
		payload, _ := core.ComposeToken(tok, signer)
		extractAndCheck(payload, tok, t)
	})
	t.Run("Audience is not correct", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Audience = "Fake test audience"
		payload, _ := core.ComposeToken(tok1, signer)
		extractAndCheck(payload, tok2, t)
	})
	t.Run("Issuer is not correct", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Issuer = "Fake Test Issuer"
		payload, _ := core.ComposeToken(tok1, signer)
		extractAndCheck(payload, tok2, t)
	})
	t.Run("Subject is not correct", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Issuer = "Fake Test Issuer"
		payload, _ := core.ComposeToken(tok1, signer)
		extractAndCheck(payload, tok2, t)
	})
	t.Run("ID must not be validated", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.ID = "fakeTestID"
		payload, _ := core.ComposeToken(tok1, signer)
		_, err := core.ExtractToken(
			string(payload),
			&_conf.Config{
				Signer:   signer,
				Audience: tok2.Audience,
				Issuer:   tok2.Issuer,
				Subject:  tok2.Subject,
				ExpireIn: 2 * time.Hour,
			},
		)
		if err != nil {
			t.Fatal("extractToken must not have an error: ", err)
		}
	})
}
