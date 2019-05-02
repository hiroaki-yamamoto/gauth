package models

// User Interface / Model

// IUser is an interface that describes functions to be implemnted.
type IUser interface {
	GetID() string // Should return the ID or username of the user.
}
