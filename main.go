package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"log"
	"os"
)

func main() {
	app := fiber.New()
	app.Use(cors.New())

	server, err := CreateServer()
	if err != nil {
		log.Fatal(err)
	}

	authGroup := app.Group("/api/auth/")
	authGroup.Post("/sign-in/", server.HandleAuthSignIn)
	authGroup.Post("/validate/", server.HandleAuthValidate)

	log.Fatal(app.Listen(os.Getenv("LISTEN_ON")))
}
