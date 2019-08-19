package clock_test

import (
	"testing"
	"time"

	"github.com/hiroaki-yamamoto/gauth/clock"
	"gotest.tools/v3/assert"
)

// Clock test

func TestNow(t *testing.T) {
	clock := clock.DefaultTime{}
	assert.Equal(t, clock.Now().Unix(), time.Now().UTC().Unix())
}
