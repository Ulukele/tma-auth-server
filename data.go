package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"strings"
)

type DBEngine struct {
	DB *gorm.DB
}

type UserModel struct {
	gorm.Model
	Id        uint   `gorm:"primaryKey"`
	Username  string `gorm:"unique"`
	Password  string
	SessionID string
}

func generateSessionId(username string, password string) string {
	slice := []string{username, password}
	bytes := []byte(strings.Join(slice, "@"))

	h := sha256.New()
	h.Write(bytes)
	res := h.Sum(nil)
	return hex.EncodeToString(res)
}

func CreateEngine() (*DBEngine, error) {
	dsn := "host=localhost user=postgres password=postgres dbname=postgres port=5432 sslmode=disable TimeZone=Asia/Novosibirsk"

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		return nil, err
	}

	if err = db.AutoMigrate(&UserModel{}); err != nil {
		return nil, err
	}

	dbe := &DBEngine{}
	dbe.DB = db
	return dbe, nil
}

func (dbe *DBEngine) createSession(username string, password string) (string, error) {
	var user = UserModel{}
	if err := dbe.DB.
		Where("Username = ? AND Password = ?", username, password).
		Take(&user).Error; err != nil {
		return "", err
	}

	user.SessionID = generateSessionId(user.Username, user.Password)
	dbe.DB.Save(&user)

	return user.SessionID, nil
}

func (dbe *DBEngine) removeSession(username string, session string) error {
	var user = UserModel{}
	if err := dbe.DB.
		Where("Username = ? AND Session_ID = ?", username, session).
		Take(&user).Error; err != nil {
		return err
	}

	err := dbe.DB.Model(&user).
		Select("SessionID").
		Updates(
			map[string]interface{}{"SessionID": gorm.Expr("NULL")}).
		Error

	if err != nil {
		return err
	}

	return nil
}

func (dbe *DBEngine) registerUser(username string, password string) error {

	var user = UserModel{Username: username, Password: password}

	var exists bool
	err := dbe.DB.Model(&user).
		Select("count(*) > 0").
		Where("Username = ?", username).
		Find(&exists).
		Error
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("such user already exists")
	}
	dbe.DB.Save(&user)

	return nil
}
