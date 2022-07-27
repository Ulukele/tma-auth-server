package main

import (
	"github.com/gofiber/fiber/v2"
	"log"
	"strconv"
)

func (s *Server) refreshToken(info UserInfo) (JwtResponse, error) {
	token, err := generateAuthJWT(info, s.signKey)
	if err != nil {
		return JwtResponse{}, err
	}
	refreshToken, err := generateRefreshJWT(info, s.signKey)
	if err != nil {
		return JwtResponse{}, err
	}
	if err := s.dbe.UpdateRefreshToken(info.Id, refreshToken); err != nil {
		return JwtResponse{}, err
	}

	return JwtResponse{JWT: token, RefreshToken: refreshToken, Id: info.Id}, nil
}

func (s *Server) HandleAuthSignIn(c *fiber.Ctx) error {
	log.Printf("handle sign-in at %s", c.Path())

	var req userAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect username and password")
	}
	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	exist, err := s.dbe.CheckUser(req.Username, req.Password)
	if err != nil || !exist {
		return fiber.NewError(fiber.StatusBadRequest, "invalid username or password")
	}
	user := &UserModel{}
	user, err = s.dbe.GetUserByUsername(req.Username)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "can't find such user")
	}

	info := UserInfo{Username: user.Username, Id: user.Id}

	response, err := s.refreshToken(info)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while create tokens")
	}
	return c.JSON(response)
}

func (s *Server) HandleAuthSignUp(c *fiber.Ctx) error {
	log.Printf("handle sign-up at %s", c.Path())

	var req userAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect username and password")
	}
	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	exist, err := s.dbe.CheckUserByUsername(req.Username)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid username or password")
	}
	if exist {
		return fiber.NewError(fiber.StatusBadRequest, "such user already exists")
	}

	user, err := s.dbe.CreateUser(req.Username, req.Password)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "can't create such user")
	}

	info := UserInfo{Username: user.Username, Id: user.Id}

	response, err := s.refreshToken(info)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while create tokens")
	}
	return c.JSON(response)
}

func (s *Server) HandleAuthValidate(c *fiber.Ctx) error {
	log.Printf("handle auth validate at %s", c.Path())

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

func (s *Server) HandleAuthRefresh(c *fiber.Ctx) error {
	log.Printf("handle auth refresh tokens at %s", c.Path())

	var req RefreshRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect refresh token")
	}
	if err := validate.Struct(req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	user, err := ParseJWT(req.RefreshToken, s.verifyKey)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while validate jwt")
	}
	if err = validate.Struct(user); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while validate jwt")
	}

	userModel, err := s.dbe.GetUserById(user.Id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "can't find user")
	}
	if userModel.RefreshToken != req.RefreshToken {
		return fiber.NewError(fiber.StatusBadRequest, "invalid refresh token")
	}

	response, err := s.refreshToken(user)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while create tokens")
	}

	return c.JSON(response)
}

func (s *Server) HandleGetUser(c *fiber.Ctx) error {
	log.Printf("handle get user at %s", c.Path())

	var req userGetRequest
	userId, err := strconv.Atoi(c.Params("userId", "not a number"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect userId")
	}
	req.Id = uint(userId)

	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	user, err := s.dbe.GetUserById(req.Id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "no such user")
	}

	info := UserResponse{Id: user.Id, Username: user.Username}
	return c.JSON(info)
}
