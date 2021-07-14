package main

import (
	"context"
	"corrlinker-frontend/app"
	"corrlinker-frontend/auth"
	"log"
	"net/url"
	"os"

	"github.com/coreos/go-oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html"
)

var (
	// Default error handler
	DefaultErrorHandler = func(c *fiber.Ctx, err error) error {
		// Default 500 statuscode
		code := fiber.StatusInternalServerError

		if e, ok := err.(*fiber.Error); ok {
			// Override status code if fiber.Error type
			code = e.Code
		}
		// Set Content-Type: text/plain; charset=utf-8
		c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)

		// Return statuscode with error message
		return c.Status(code).SendString(err.Error())
	}
)

func Start() {
	engine := html.New("./views", ".html")
	engine.Reload(true)
	engine.Debug(false)

	// Fiber instance
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Server static assets
	app.Static("/", "./public", fiber.Static{
		Compress: false,
	})

	// Middlewares
	app.Use(
		// Add CORS to each route.
		cors.New(),
		// Add simple logger.
		logger.New(),
	)

	// Routes
	app.Get("/", Home)
	app.Get("/login", Login)
	app.Get("/logout", Logout)
	app.Get("/callback", Callback)
	app.Get("/user", AuthRequired, User)

	// Start server
	log.Fatal(app.Listen(":3000"))
}

func Home(c *fiber.Ctx) error {
	sess, err := app.Store.Get(c)
	if err != nil {
		return DefaultErrorHandler(c, err)
	}
	log.Println("Home Session:", sess.ID())

	if sess.Get("profile") != nil {
		return c.Redirect("/user", 303)
	}
	sess.Save()

	return c.Render("home", nil)
}

func Login(c *fiber.Ctx) error {
	sess, err := app.Store.Get(c)
	if err != nil {
		return DefaultErrorHandler(c, err)
	}
	log.Println("Login Session:", sess.ID())

	if sess.Get("profile") != nil {
		return c.Redirect("/user", 303)
	}

	state := sess.ID()
	sess.Save()

	authenticator, err := auth.NewAuthenticator()
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Invalid auth")
	}

	return c.Redirect(authenticator.Config.AuthCodeURL(state), 301)
}

func Callback(c *fiber.Ctx) error {
	sess, err := app.Store.Get(c)
	if err != nil {
		return DefaultErrorHandler(c, err)
	}
	log.Println("Callback Session:", sess.ID())
	log.Println("cQuery State ID: ", c.Query("state"))

	if sess.Get("profile") != nil {
		return c.Redirect("/user", 303)
	}

	if c.Query("state") != sess.ID() {
		log.Println("Invalid session state")
		return c.Redirect("/Login", 303)
	}

	authenticator, err := auth.NewAuthenticator()
	if err != nil {
		return DefaultErrorHandler(c, err)
	}

	token, err := authenticator.Config.Exchange(context.TODO(), c.Query("code"))
	if err != nil {
		log.Printf("no token found: %v", err)
		return c.SendStatus(401)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return fiber.NewError(fiber.StatusInternalServerError, "No id_token field in oauth2 token.")
	}

	oidcConfig := &oidc.Config{
		ClientID: os.Getenv("AUTH0_CLIENT_ID"),
	}

	idToken, err := authenticator.Provider.Verifier(oidcConfig).Verify(context.TODO(), rawIDToken)

	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to verify ID Token: "+err.Error())
	}

	// Getting now the userInfo
	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		return DefaultErrorHandler(c, err)
	}

	sess.Set("id_token", rawIDToken)
	sess.Set("access_token", token.AccessToken)
	sess.Set("profile", profile)
	err = sess.Save()
	if err != nil {
		return DefaultErrorHandler(c, err)
	}

	// Redirect to logged in page
	return c.Redirect("/user", 303)
}

func User(c *fiber.Ctx) error {
	sess, err := app.Store.Get(c)
	if err != nil {
		return DefaultErrorHandler(c, err)
	}
	log.Println("User Session:", sess.ID())

	return c.Render("user", sess.Get("profile"))
}

// middleware
func AuthRequired(c *fiber.Ctx) error {
	sess, err := app.Store.Get(c)
	if err != nil {
		return DefaultErrorHandler(c, err)
	}
	log.Println("AuthRequired Session:", sess.ID())

	if sess.Get("profile") == nil {
		return c.Redirect("/", 303)
	}

	return c.Next()
}

func Logout(c *fiber.Ctx) error {
	sess, err := app.Store.Get(c)
	if err != nil {
		return DefaultErrorHandler(c, err)
	}
	log.Println("Logout Session:", sess.ID())
	sess.Destroy()

	domain := os.Getenv("AUTH0_DOMAIN")

	logoutUrl, err := url.Parse("https://" + domain)

	if err != nil {
		return DefaultErrorHandler(c, err)
	}

	logoutUrl.Path += "/v2/logout"
	parameters := url.Values{}

	var scheme string
	if c.Protocol() == "http" {
		scheme = "http"
	} else {
		scheme = "https"
	}

	returnTo, err := url.Parse(scheme + "://" + c.Hostname())
	if err != nil {
		return DefaultErrorHandler(c, err)
	}
	parameters.Add("returnTo", returnTo.String())
	parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	logoutUrl.RawQuery = parameters.Encode()

	return c.Redirect(logoutUrl.String(), 301)
}
