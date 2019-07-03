package config_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp/cmpopts"
	_conf "github.com/hiroaki-yamamoto/gauth/config"

	"github.com/gbrlsnchs/jwt/v2"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

// Config Test

func TestConfigNew(t *testing.T) {
	cookieConfig := _conf.CookieConfig{
		"/", "localhost", false, true, http.SameSiteLaxMode,
	}
	config := &_conf.Config{
		cookieConfig,
		"session",
		_conf.Header,
		jwt.NewHS256("test"),
		"test audience",
		"test issuer",
		"test subject",
		2 * time.Hour,
	}
	newConfig, err := _conf.New(
		config.SessionName,
		config.MiddlewareType,
		config.Signer,
		config.Audience,
		config.Issuer,
		config.Subject,
		config.ExpireIn,
		config.CookieConfig,
	)
	assert.NilError(t, err)
	assert.DeepEqual(
		t, *newConfig, *config,
		cmpopts.IgnoreFields((*config), "Signer"),
	)
}

func TestConfigNewWithNegExp(t *testing.T) {
	cookieConfig := _conf.CookieConfig{
		"/", "localhost", false, true, http.SameSiteLaxMode,
	}
	config, err := _conf.New(
		"session",
		_conf.Header,
		jwt.NewHS256("test"),
		"test audience",
		"test issuer",
		"test subject",
		-9*time.Hour,
		cookieConfig,
	)
	assert.Error(t, err, "expireIn must be 0-included positive time.Duration")
	assert.Assert(t, cmp.Nil(config))
}

func TestConfigNewWithZeroExp(t *testing.T) {
	cookieConfig := _conf.CookieConfig{
		"/", "localhost", false, true, http.SameSiteLaxMode,
	}
	config := &_conf.Config{
		SessionName:    "session",
		MiddlewareType: _conf.Header,
		Signer:         jwt.NewHS256("test"),
		Audience:       "test audience",
		Issuer:         "test issuer",
		Subject:        "test subject",
		CookieConfig:   cookieConfig,
	}
	newConfig, err := _conf.New(
		config.SessionName,
		config.MiddlewareType,
		config.Signer,
		config.Audience,
		config.Issuer,
		config.Subject,
		config.ExpireIn,
		config.CookieConfig,
	)
	assert.NilError(t, err)
	assert.DeepEqual(
		t, *newConfig, *config,
		cmpopts.IgnoreFields((*config), "Signer"),
		cmpopts.IgnoreFields((*config), "ExpireIn"),
	)
	assert.Assert(t, config.ExpireIn != newConfig.ExpireIn)
	assert.Equal(t, newConfig.ExpireIn, 3600*time.Minute)
}
