package middleware_test

import (
	"testing"
	"time"

	"github.com/hiroaki-yamamoto/gauth/middleware"
	"gotest.tools/assert"
)

// Clock test

func TestNow(t *testing.T) {
	clock := middleware.DefaultTime{}
	assert.Equal(t, clock.Now().Unix(), time.Now().UTC().Unix())
}
