package app

import (
	"encoding/gob"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/utils"
	"github.com/joho/godotenv"
)

// Config defines the config for middleware.
type Config struct {
	// Allowed session duration
	// Optional. Default value 24 * time.Hour
	Expiration time.Duration

	// Storage interface to store the session data
	// Optional. Default value memory.New()
	Storage fiber.Storage

	// Name of the session cookie. This cookie will store session key.
	// Optional. Default value "session_id".
	CookieName string

	// Domain of the CSRF cookie.
	// Optional. Default value "".
	CookieDomain string

	// Path of the CSRF cookie.
	// Optional. Default value "".
	CookiePath string

	// Indicates if CSRF cookie is secure.
	// Optional. Default value false.
	CookieSecure bool

	// Indicates if CSRF cookie is HTTP only.
	// Optional. Default value false.
	CookieHTTPOnly bool

	// Indicates if CSRF cookie is HTTP only.
	// Optional. Default value false.
	CookieSameSite string

	// KeyGenerator generates the session key.
	// Optional. Default value utils.UUID
	KeyGenerator func() string
}

var (
	Store *session.Store

	ConfigDefault = session.Config{
		Expiration:   1 * time.Hour,
		CookieName:   "session_id",
		KeyGenerator: utils.UUID,
	}
)

func Init() error {
	err := godotenv.Load()
	if err != nil {
		log.Print(err.Error())
		return err
	}

	Store = session.New(ConfigDefault)
	gob.Register(map[string]interface{}{})
	return nil
}
