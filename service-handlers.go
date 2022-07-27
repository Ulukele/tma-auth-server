package main

import (
	"github.com/gofiber/fiber/v2"
	"log"
	"strconv"
)

func (s *Server) refreshServiceToken(info ServiceInfo) (JwtResponse, error) {
	token, err := generateAuthServiceJWT(info, s.signKey)
	if err != nil {
		return JwtResponse{}, err
	}
	refreshToken, err := generateServiceRefreshJWT(info, s.signKey)
	if err != nil {
		return JwtResponse{}, err
	}
	if err := s.dbe.UpdateServiceRefreshToken(info.Id, refreshToken); err != nil {
		return JwtResponse{}, err
	}

	return JwtResponse{JWT: token, RefreshToken: refreshToken, Id: info.Id}, nil
}

func (s *Server) HandleAuthServiceSignIn(c *fiber.Ctx) error {
	log.Printf("handle service sign-in at %s", c.Path())

	var req serviceAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect name and secretKey")
	}
	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	exist, err := s.dbe.CheckService(req.Name, req.SecretKey)
	if err != nil || !exist {
		return fiber.NewError(fiber.StatusBadRequest, "invalid name or secretKey")
	}
	service := &ServiceModel{}
	service, err = s.dbe.GetServiceByName(req.Name)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "can't find such service")
	}

	info := ServiceInfo{Name: service.Name, Id: service.Id}

	response, err := s.refreshServiceToken(info)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while create tokens")
	}
	return c.JSON(response)
}

func (s *Server) HandleAuthServiceCreate(c *fiber.Ctx) error {
	log.Printf("handle create service at %s", c.Path())

	var req serviceAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect name and secretKey")
	}
	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	exist, err := s.dbe.CheckServiceByName(req.Name)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid name or secretKey")
	}
	if exist {
		return fiber.NewError(fiber.StatusBadRequest, "such service already exists")
	}

	service, err := s.dbe.CreateService(req.Name, req.SecretKey)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "can't create such service")
	}

	info := ServiceInfo{Name: service.Name, Id: service.Id}

	response, err := s.refreshServiceToken(info)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while create tokens")
	}
	return c.JSON(response)
}

func (s *Server) HandleAuthServiceRefresh(c *fiber.Ctx) error {
	log.Printf("handle auth service refresh tokens at %s", c.Path())

	var req RefreshRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect refresh token")
	}
	if err := validate.Struct(req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	service, err := ParseServiceJWT(req.RefreshToken, s.verifyKey)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while validate jwt")
	}
	if err = validate.Struct(service); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while validate jwt")
	}

	serviceModel, err := s.dbe.GetServiceById(service.Id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "can't find service")
	}
	if serviceModel.RefreshToken != req.RefreshToken {
		return fiber.NewError(fiber.StatusBadRequest, "invalid refresh token")
	}

	response, err := s.refreshServiceToken(service)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while create tokens")
	}

	return c.JSON(response)
}

func (s *Server) HandleGetUserToken(c *fiber.Ctx) error {
	log.Printf("handle get user token at %s", c.Path())

	var req serviceUserRequest
	userId, err := strconv.Atoi(c.Params("userId", "not a number"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect userId")
	}
	req.UserId = uint(userId)

	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	service, err := ParseServiceJWT(req.JWT, s.verifyKey)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while validate jwt")
	}
	if err = validate.Struct(service); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "error while validate jwt")
	}

	inService, err := s.dbe.CheckUserInService(req.UserId, req.ServiceUsername, service.Id)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "no such user in service")
	}

	if !inService {
		return fiber.NewError(fiber.StatusBadRequest, "no such user in service")
	}

	user, err := s.dbe.GetUserById(req.UserId)
	if err != nil {
		return err
	}

	info := UserInfo{Username: user.Username, Id: user.Id}
	token, err := generateAuthJWT(info, s.signKey)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "can't generate user token")
	}

	return c.JSON(SingleJwtResponse{Id: user.Id, JWT: token})
}
