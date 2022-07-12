package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"log"
)

func main() {
	app := fiber.New()
	app.Use(cors.New())

	server, err := CreateServer()
	if err != nil {
		log.Fatal(err)
	}

	userGroup := app.Group("/api/user/")
	userGroup.Post("/sign-in/", server.HandleSignIn)
	userGroup.Post("/sign-up/", server.HandleSignUp)
	userGroup.Post("/sign-out/", server.HandleSignOut)

	log.Fatal(app.Listen(":8080"))
}
