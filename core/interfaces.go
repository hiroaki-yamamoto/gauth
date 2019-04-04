package core

// IUser specifies the structure that is implementeng the minimum functions for
// authentication.
type IUser interface {
	GetUserName() string
	GetPassword() string
}
