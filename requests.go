package main

type userAuthRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type serviceAuthRequest struct {
	Name      string `json:"name" validate:"required"`
	SecretKey string `json:"secretKey" validate:"required"`
}

type serviceUserRequest struct {
	JWT             string `json:"jwt" validate:"required"`
	ServiceUsername string `json:"serviceUsername" validate:"required"`
	UserId          uint   `json:"userId" validate:"required"`
}

type userGetRequest struct {
	Id uint `json:"id" validate:"required"`
}

type AuthRequest struct {
	JWT string `json:"jwt" validate:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}
