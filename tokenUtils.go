package main

import (
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt"
	"time"
)

type UserInfo struct {
	Id       uint   `json:"id" validate:"required"`
	Username string `json:"username" validate:"required"`
}

type CustomClaims struct {
	*jwt.StandardClaims
	TokenType string
	UserInfo
}

func ParseJWT(tokenString string, verifyKey *rsa.PublicKey) (UserInfo, error) {

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return UserInfo{}, nil
	}

	if !token.Valid {
		return UserInfo{}, fmt.Errorf("invalid jwt")
	}
	claims := token.Claims.(*CustomClaims)

	return claims.UserInfo, nil
}

func generateJWT(info UserInfo, expDuration time.Duration, signKey *rsa.PrivateKey) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims = &CustomClaims{
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expDuration).Unix(),
		},
		"level1",
		info,
	}

	return token.SignedString(signKey)
}

func generateAuthJWT(info UserInfo, signKey *rsa.PrivateKey) (string, error) {
	return generateJWT(info, time.Minute*5, signKey)
}

func generateRefreshJWT(info UserInfo, signKey *rsa.PrivateKey) (string, error) {
	return generateJWT(info, time.Minute*20, signKey)
}
