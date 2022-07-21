package main

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"log"
)

type Server struct {
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
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
	return s, nil
}

// Validator
var validate = validator.New()

type userInfoRequest struct {
	Username string `json:"username" validate:"required"`
	Id       uint   `json:"id" validate:"required"`
}

type AuthRequest struct {
	JWT string `jon:"jwt" validate:"required"`
}

type JwtResponse struct {
	JWT string `json:"jwt"`
}

func (s *Server) HandleAuthSignIn(c *fiber.Ctx) error {
	log.Printf("handle sign in %s", c.Path())

	var req userInfoRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect username and id")
	}
	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	info := UserInfo{Username: req.Username, Id: req.Id}

	token, err := generateJWT(info, s.signKey)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "error while create jwt")
	}
	return c.JSON(JwtResponse{JWT: token})
}

func (s *Server) HandleAuthValidate(c *fiber.Ctx) error {
	log.Printf("handle auth validate in %s", c.Path())

	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect jwt")
	}
	if err := validate.Struct(req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	user, err := ParseJWT(req.JWT, s.verifyKey)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while validate jwt")
	}
	if err = validate.Struct(user); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while validate jwt")
	}
	return c.JSON(user)
}
