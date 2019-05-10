package core

import (
	"net/http"
	"time"

	"github.com/hiroaki-yamamoto/gauth/clock"
	"github.com/hiroaki-yamamoto/gauth/config"
	"github.com/hiroaki-yamamoto/gauth/models"
)

// Login sets the specified user to the session field that is specified on the
// config.
func Login(
	w http.ResponseWriter,
	conf *config.Config, user models.IUser,
) error {
	token, err := ComposeID(user.GetID(), conf)
	if err != nil {
		return err
	}
	if conf.MiddlewareType == config.Header {
		w.Header().Add("X-"+conf.SessionName, string(token))
		return nil
	}
	http.SetCookie(w, &http.Cookie{
		Name:     conf.SessionName,
		Value:    string(token),
		Path:     conf.Path,
		Domain:   conf.Domain,
		Expires:  clock.Clock.Now().Add(conf.ExpireIn),
		MaxAge:   int(conf.ExpireIn / time.Second),
		Secure:   conf.Secure,
		HttpOnly: conf.HTTPOnly,
		SameSite: conf.SameSite,
	})
	return nil
}
