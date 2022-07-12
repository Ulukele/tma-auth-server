package main

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"log"
)

type Server struct {
	engine *DBEngine
}

func CreateServer() (*Server, error) {
	engine, err := CreateEngine()
	if err != nil {
		return nil, err
	}

	s := &Server{}
	s.engine = engine
	return s, nil
}

// Validator
var validate = validator.New()

type userInfoRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type sessionResponse struct {
	SessionID string `json:"sessionID" validate:"required"`
}

func (s *Server) HandleSignIn(c *fiber.Ctx) error {
	log.Printf("handle sign in %s", c.Path())

	userInfo := userInfoRequest{}
	if err := c.BodyParser(&userInfo); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect username and password")
	}
	err := validate.Struct(userInfo)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	sessionID, err := s.engine.createSession(userInfo.Username, userInfo.Password)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "wrong username or password")
	}

	resp := sessionResponse{SessionID: sessionID}
	return c.JSON(resp)
}

func (s *Server) HandleSignOut(c *fiber.Ctx) error {
	log.Printf("handle sign out %s", c.Path())

	type userSignOutRequest struct {
		Username  string `json:"username" validate:"required"`
		SessionID string `json:"sessionID" validate:"required"`
	}
	signOutRequest := userSignOutRequest{}
	if err := c.BodyParser(&signOutRequest); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect username and sessionID")
	}
	err := validate.Struct(signOutRequest)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	if err := s.engine.removeSession(signOutRequest.Username, signOutRequest.SessionID); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "wrong sessionID")
	}

	resp := sessionResponse{SessionID: signOutRequest.SessionID}
	return c.JSON(resp)
}

func (s *Server) HandleSignUp(c *fiber.Ctx) error {
	log.Printf("handle sign up %s", c.Path())

	userInfo := userInfoRequest{}
	if err := c.BodyParser(&userInfo); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect username and password")
	}
	err := validate.Struct(userInfo)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	if err := s.engine.registerUser(userInfo.Username, userInfo.Password); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "unable to register user")
	}

	sessionID, err := s.engine.createSession(userInfo.Username, userInfo.Password)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "wrong username or password")
	}

	resp := sessionResponse{SessionID: sessionID}
	return c.JSON(resp)
}
