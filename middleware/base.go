package middleware

import (
	"encoding/json"
	"log"
	"net/http"

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
			iuser, ok := user.(models.IUser)
			if ok {
				core.Login(w, config, iuser)
				// There's nothing errors in this case. Therefore, no need to
				// check whether the error is nil or not.
			} else {
				log.Println("Authorized user not detected")
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

			iuser, ok := user.(models.IUser)
			if ok {
				core.Login(w, config, iuser)
				// There's nothing errors in this case. Therefore, no need to
				// check whether the error is nil or not.
			} else {
				log.Println("Authorized user not detected")
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
