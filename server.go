package main

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"log"
	"os"
	"strconv"
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

	contentGroup := apiGroup.Group("/content/")
	concreteUserGroup := contentGroup.Group("/user/:userId/")
	concreteUserGroup.Get("/", s.HandleGetUser)
	userTelegramGroup := concreteUserGroup.Group("/telegram/")
	userTelegramGroup.Post("/", s.HandleUpdateTelegramUsername)
	userTelegramGroup.Delete("/", s.HandleDeleteTelegramUsername)

	internalGroup := apiGroup.Group("/internal/")
	telegramGroup := internalGroup.Group("/telegram/")
	telegramGroup.Post("/add/", s.HandleUpdateTelegramId)

	return app.Listen(os.Getenv("LISTEN_ON"))
}

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

func (s *Server) HandleUpdateTelegramUsername(c *fiber.Ctx) error {
	log.Printf("handle update telegram username at %s", c.Path())

	var req UpdateTelegramUsername
	userId, err := strconv.Atoi(c.Params("userId", "not a number"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect userId")
	}
	userId_, err := strconv.Atoi(c.Get("UserId", "not a number"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect UserId in header")
	}
	if userId != userId_ {
		return fiber.NewError(fiber.StatusBadRequest, "failed to auth")
	}
	req.UserId = uint(userId)
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect telegramUsername")
	}

	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	err = s.dbe.UpdateTelegramUsername(req.UserId, req.TelegramUsername)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "can't update telegram username")
	}

	return c.JSON("")
}

func (s *Server) HandleDeleteTelegramUsername(c *fiber.Ctx) error {
	log.Printf("handle delete telegram username at %s", c.Path())

	var req DeleteTelegramUsername

	userId, err := strconv.Atoi(c.Params("userId", "not a number"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect userId")
	}
	userId_, err := strconv.Atoi(c.Get("UserId", "not a number"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect UserId in header")
	}
	if userId != userId_ {
		return fiber.NewError(fiber.StatusBadRequest, "failed to auth")
	}
	req.UserId = uint(userId)

	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	err = s.dbe.DeleteTelegramRef(req.UserId)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "can't delete telegram username")
	}

	return c.JSON("")
}

func (s *Server) HandleUpdateTelegramId(c *fiber.Ctx) error {
	log.Printf("handle update telegram id at %s", c.Path())

	var req UpdateTelegramId

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "expect userId, telegramUsername and telegramId")
	}

	if err := validate.Struct(req); err != nil {
		log.Printf(err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "validation error")
	}

	err := s.dbe.UpdateTelegramUserId(req.UserId, req.TelegramUsername, req.TelegramId)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "can't update telegram id")
	}

	return c.JSON("")
}
