package main

type userAuthRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type userGetRequest struct {
	Id uint `json:"id" validate:"required"`
}

type AuthRequest struct {
	JWT string `jon:"jwt" validate:"required"`
}
