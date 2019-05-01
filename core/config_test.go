package core

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/gbrlsnchs/jwt"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

// Config Test

func TestConfigNew(t *testing.T) {
	config := &Config{
		jwt.NewHS256("test"),
		"test audience",
		"test issuer",
		"test subject",
		2 * time.Hour,
	}
	newConfig, err := New(
		config.Signer,
		config.Audience,
		config.Issuer,
		config.Subject,
		config.ExpireIn,
	)
	assert.NilError(t, err)
	assert.DeepEqual(
		t, *newConfig, *config,
		cmpopts.IgnoreFields((*config), "Signer"),
	)
}

func TestConfigNewWithNegExp(t *testing.T) {
	config, err := New(
		jwt.NewHS256("test"),
		"test audience",
		"test issuer",
		"test subject",
		-9*time.Hour,
	)
	assert.Error(t, err, "expireIn must be 0-included positive time.Duration")
	assert.Assert(t, cmp.Nil(config))
}

func TestConfigNewWithZeroExp(t *testing.T) {
	config := &Config{
		Signer:   jwt.NewHS256("test"),
		Audience: "test audience",
		Issuer:   "test issuer",
		Subject:  "test subject",
	}
	newConfig, err := New(
		config.Signer,
		config.Audience,
		config.Issuer,
		config.Subject,
		config.ExpireIn,
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
