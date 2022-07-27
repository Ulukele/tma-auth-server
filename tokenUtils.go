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

type ServiceInfo struct {
	Id   uint   `json:"id" validate:"required"`
	Name string `json:"name" validate:"required"`
}

type CustomClaims struct {
	*jwt.StandardClaims
	TokenType string
	UserInfo
}

type ServiceCustomClaims struct {
	*jwt.StandardClaims
	TokenType string
	ServiceInfo
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

func ParseServiceJWT(tokenString string, verifyKey *rsa.PublicKey) (ServiceInfo, error) {

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return ServiceInfo{}, nil
	}

	if !token.Valid {
		return ServiceInfo{}, fmt.Errorf("invalid jwt")
	}
	claims := token.Claims.(*ServiceCustomClaims)

	return claims.ServiceInfo, nil
}

func generateServiceJWT(info ServiceInfo, expDuration time.Duration, signKey *rsa.PrivateKey) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims = &ServiceCustomClaims{
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(expDuration).Unix(),
		},
		"level1",
		info,
	}

	return token.SignedString(signKey)
}

func generateAuthServiceJWT(info ServiceInfo, signKey *rsa.PrivateKey) (string, error) {
	return generateServiceJWT(info, time.Minute*10, signKey)
}

func generateServiceRefreshJWT(info ServiceInfo, signKey *rsa.PrivateKey) (string, error) {
	return generateServiceJWT(info, time.Minute*30, signKey)
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
