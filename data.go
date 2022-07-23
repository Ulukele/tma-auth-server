package main

import (
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
)

type DBEngine struct {
	DB *gorm.DB
}

type DBConfig struct {
	Host     string
	User     string
	Password string
	Name     string
	Port     string
	SSLMode  string
	Tz       string
}

func NewDBEngine(dbc DBConfig) (*DBEngine, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		dbc.Host,
		dbc.User,
		dbc.Password,
		dbc.Name,
		dbc.Port,
		dbc.SSLMode,
		dbc.Tz)
	log.Printf("Use config: %s", dsn)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		return nil, err
	}

	dbe := &DBEngine{}
	dbe.DB = db
	return dbe, nil
}

func (dbe *DBEngine) CreateUser(username string, password string) (*UserModel, error) {
	user := &UserModel{Username: username, Password: password}
	if err := dbe.DB.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func (dbe *DBEngine) CheckUser(username string, password string) (bool, error) {
	user := &UserModel{}
	var exists bool
	if err := dbe.DB.
		Model(&user).
		Select("count(*) > 0").
		Where("username = ? AND password = ?", username, password).
		Find(&exists).
		Error; err != nil {
		return false, err
	}

	return exists, nil
}

func (dbe *DBEngine) CheckUserByUsername(username string) (bool, error) {
	user := &UserModel{}
	var exists bool
	if err := dbe.DB.
		Model(&user).
		Select("count(*) > 0").
		Where("username = ?", username).
		Find(&exists).
		Error; err != nil {
		return false, err
	}

	return exists, nil
}

func (dbe *DBEngine) GetUserById(userId uint) (*UserModel, error) {
	user := &UserModel{}
	if err := dbe.DB.
		Where("Id = ?", userId).
		Take(&user).
		Error; err != nil {
		return nil, err
	}

	return user, nil
}

func (dbe *DBEngine) GetUserByUsername(username string) (*UserModel, error) {
	user := &UserModel{}
	if err := dbe.DB.
		Where("username = ?", username).
		Take(&user).
		Error; err != nil {
		return nil, err
	}

	return user, nil
}
