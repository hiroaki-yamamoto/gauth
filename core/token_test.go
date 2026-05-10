package core_test

import (
	"encoding/json"
	"testing"
	"time"

	"codeberg.org/gbrlsnchs/jwt"
	"github.com/google/go-cmp/cmp"
	_conf "github.com/hiroaki-yamamoto/gauth/config"
	"github.com/hiroaki-yamamoto/gauth/core"
	"gotest.tools/v3/assert"
)

func mustHS256(k string) jwt.Signer {
	for len(k) < 32 {
		k += "0"
	}
	s, err := jwt.NewHS256([]byte(k))
	if err != nil {
		panic(err)
	}
	return s
}

var now = time.Now().UTC()

func GetFixture() *jwt.JWT[jwt.None] {
	return &jwt.JWT[jwt.None]{
		Claims: jwt.Claims[jwt.None]{
			Issuer:     "test",
			Subject:    "test subject",
			Audience:   jwt.Audience{"test audience"},
			Expiration: jwt.ConvertTime(now.Add(2 * time.Hour)),
			NotBefore:  jwt.ConvertTime(now),
			IssuedAt:   jwt.ConvertTime(now),
			JWTID:      "test username",
		},
	}
}

func TestNormalTokenFunc(t *testing.T) {
	token := GetFixture()
	config := _conf.Config{
		Signer:   mustHS256("test secret key"),
		Audience: token.Claims.Audience[0],
		Issuer:   token.Claims.Issuer,
		Subject:  token.Claims.Subject,
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
		composedToken, err := core.ComposeID(token.Claims.JWTID, &config)
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
	signer := mustHS256("test secret key")
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
	signer := mustHS256("test secret key")
	tok := map[string]float64{"Test": 1.0, "exp": 123.456}
	payload, _ := json.Marshal(tok)
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
	assert.ErrorContains(t, err, "jwt: token is malformed")
	assert.Assert(t, exTok == nil, exTok)
}

func TestVerificationFailure(t *testing.T) {
	composeSigner := mustHS256("test secret key")
	extractSigner := mustHS256("really test secret key")
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
	signer := mustHS256("test secret key")
	extractAndCheck := func(payload []byte, tok *jwt.JWT[jwt.None], t *testing.T) {
		extracted, err := core.ExtractToken(
			string(payload),
			&_conf.Config{
				Signer:   signer,
				Audience: tok.Claims.Audience[0],
				Issuer:   tok.Claims.Issuer,
				Subject:  tok.Claims.Subject,
				ExpireIn: 2 * time.Hour,
			},
		)
		if err == nil {
			t.Fatal("extractToken must have an error: ", extracted)
		}
	}
	t.Run("Issued at is Future", func(t *testing.T) {
		tok := GetFixture()
		tok.Claims.IssuedAt = jwt.ConvertTime(now.Add(5 * time.Hour))
		payload, _ := core.ComposeToken(tok, signer)
		extractAndCheck(payload, tok, t)
	})
	t.Run("Already Expired", func(t *testing.T) {
		tok := GetFixture()
		tok.Claims.Expiration = jwt.ConvertTime(now.Add(-5 * time.Hour))
		payload, _ := core.ComposeToken(tok, signer)
		extractAndCheck(payload, tok, t)
	})
	t.Run("Audience is not correct", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Claims.Audience = jwt.Audience{"Fake test audience"}
		payload, _ := core.ComposeToken(tok1, signer)
		extractAndCheck(payload, tok2, t)
	})
	t.Run("Issuer is not correct", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Claims.Issuer = "Fake Test Issuer"
		payload, _ := core.ComposeToken(tok1, signer)
		extractAndCheck(payload, tok2, t)
	})
	t.Run("Subject is not correct", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Claims.Subject = "Fake Test Issuer"
		payload, _ := core.ComposeToken(tok1, signer)
		extractAndCheck(payload, tok2, t)
	})
	t.Run("ID must not be validated", func(t *testing.T) {
		tok1 := GetFixture()
		tok2 := GetFixture()
		tok2.Claims.JWTID = "fakeTestID"
		payload, _ := core.ComposeToken(tok1, signer)
		_, err := core.ExtractToken(
			string(payload),
			&_conf.Config{
				Signer:   signer,
				Audience: tok2.Claims.Audience[0],
				Issuer:   tok2.Claims.Issuer,
				Subject:  tok2.Claims.Subject,
				ExpireIn: 2 * time.Hour,
			},
		)
		if err != nil {
			t.Fatal("extractToken must not have an error: ", err)
		}
	})
}
