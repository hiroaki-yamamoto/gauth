package middleware

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/hiroaki-yamamoto/gauth/clock"
	"github.com/hiroaki-yamamoto/gauth/config"
	_conf "github.com/hiroaki-yamamoto/gauth/config"
	"github.com/hiroaki-yamamoto/gauth/core"
	"github.com/hiroaki-yamamoto/gauth/models"
)

// Error represents an error.
type Error struct {
	Message string `json:"message,omitempty"`
}

func processError(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
	err error,
	failOnError bool,
) {
	log.Print(err)
	if failOnError {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]Error{
			"errors": []Error{Error{"Not Authorized."}},
		})
		return
	}
	next.ServeHTTP(w, r)
}

func tokenizeUser(
	u interface{},
	w http.ResponseWriter,
	config *_conf.Config,
) ([]byte, error) {
	respUser, ok := u.(models.IUser)
	if !ok {
		return nil, errors.New("Authorized user not detected")
	}
	return core.ComposeID(respUser.GetID(), config)
}

func cookieMiddlewareBase(
	con interface{},
	findUserFunc FindUser,
	config *_conf.Config,
	failOnError bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(config.SessionName)
			if err != nil {
				processError(w, r, next, err, failOnError)
				return
			}
			user, err := JwtToUser(c.Value, findUserFunc, con, config)
			if err != nil {
				processError(w, r, next, err, failOnError)
				return
			}
			if tok, err := tokenizeUser(user, w, config); err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     config.SessionName,
					Value:    string(tok),
					Path:     config.Path,
					Domain:   config.Domain,
					Expires:  clock.Clock.Now().Add(config.ExpireIn),
					MaxAge:   int(config.ExpireIn / time.Second),
					Secure:   config.Secure,
					HttpOnly: config.HTTPOnly,
					SameSite: config.SameSite,
				})
			} else {
				log.Print("Composing token failed: ", err)
			}
			next.ServeHTTP(w, SetUser(r, user))
		})
	}
}

func headerMiddlewareBase(
	con interface{},
	findUserFunc FindUser,
	config *_conf.Config,
	failOnError bool,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := r.Header.Get(config.SessionName)
			user, err := JwtToUser(c, findUserFunc, con, config)
			if err != nil {
				processError(w, r, next, err, failOnError)
				return
			}

			if tok, err := tokenizeUser(user, w, config); err == nil {
				w.Header().Set("X-"+config.SessionName, string(tok))
			} else {
				log.Print("Composing token failed: ", err)
			}

			next.ServeHTTP(w, SetUser(r, user))
		})
	}
}

func middlewareBase(
	con interface{},
	findUserFunc FindUser,
	conf *config.Config,
	failOnError bool,
) func(http.Handler) http.Handler {
	if conf.MiddlewareType == config.Header {
		return headerMiddlewareBase(con, findUserFunc, conf, failOnError)
	}
	return cookieMiddlewareBase(con, findUserFunc, conf, failOnError)
}
