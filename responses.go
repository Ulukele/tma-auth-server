package main

type JwtResponse struct {
	Id           uint   `json:"id"`
	JWT          string `json:"jwt"`
	RefreshToken string `json:"refreshToken"`
}

type UserResponse struct {
	Id       uint   `json:"id"`
	Username string `json:"username"`
}
