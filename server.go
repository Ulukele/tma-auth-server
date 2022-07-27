package main

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"os"
)

// Validator
var validate = validator.New()

type Server struct {
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	dbe       *DBEngine
}

func genKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey

	return privateKey, publicKey, nil
}

func CreateServer() (*Server, error) {
	s := &Server{}

	var err error
	if s.signKey, s.verifyKey, err = genKeys(); err != nil {
		return nil, err
	}

	// configure content db engine
	// from environment
	aDBC := DBConfig{
		Host:     os.Getenv("POSTGRES_HOST"),
		User:     os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		Name:     os.Getenv("POSTGRES_NAME"),
		Port:     os.Getenv("POSTGRES_PORT"),
		SSLMode:  "disable",
		Tz:       os.Getenv("POSTGRES_TZ"),
	}
	dbe, err := NewDBEngine(aDBC)
	if err != nil {
		return nil, err
	}
	err = dbe.initTables()
	if err != nil {
		return nil, err
	}
	s.dbe = dbe

	return s, nil
}

func (s *Server) StartApp() error {
	app := fiber.New()
	app.Use(cors.New())

	apiGroup := app.Group("/api/v1/")

	authGroup := apiGroup.Group("/auth/")
	authGroup.Post("/sign-in/", s.HandleAuthSignIn)
	authGroup.Post("/sign-up/", s.HandleAuthSignUp)
	authGroup.Post("/validate/", s.HandleAuthValidate)
	authGroup.Post("/refresh/", s.HandleAuthRefresh)

	// Still not implemented completely
	//serviceGroup := authGroup.Group("/service/")
	//serviceGroup.Post("/create/", s.HandleAuthServiceCreate)
	//serviceGroup.Post("/sign-in/", s.HandleAuthServiceSignIn)
	//serviceGroup.Post("/refresh/", s.HandleAuthServiceRefresh)
	//serviceGroup.Get("/get-token/:userId/")

	contentGroup := apiGroup.Group("/content/")
	concreteUserGroup := contentGroup.Group("/user/:userId/")
	concreteUserGroup.Get("/", s.HandleGetUser)
	return app.Listen(os.Getenv("LISTEN_ON"))
}
