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

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

type UpdateTelegramUsername struct {
	UserId           uint   `json:"userId" validate:"required"`
	TelegramUsername string `json:"telegramUsername" validate:"required"`
}

type DeleteTelegramUsername struct {
	UserId uint `json:"userId" validate:"required"`
}

type UpdateTelegramId struct {
	UserId           uint   `json:"userId" validate:"required"`
	TelegramUsername string `json:"telegramUsername" validate:"required"`
	TelegramId       string `json:"telegramId" validate:"required"`
}
