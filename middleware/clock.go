package middleware

// Clock interface, structure, and instance

import "time"

type (
	// Time is an interface for time mocking
	Time interface {
		Now() time.Time
	}

	// DefaultTime is a default structure that implements Time interface
	DefaultTime struct{}
)

// Now returns now.
func (me DefaultTime) Now() time.Time {
	return time.Now().UTC()
}

// Clock is an instance of clock
var Clock Time = DefaultTime{}
