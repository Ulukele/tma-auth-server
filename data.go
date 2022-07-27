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

func (dbe *DBEngine) CreateService(name string, secretKey string) (*ServiceModel, error) {
	service := &ServiceModel{Name: name, SecretKey: secretKey}
	if err := dbe.DB.Create(service).Error; err != nil {
		return nil, err
	}
	return service, nil
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

func (dbe *DBEngine) CheckService(name string, secretKey string) (bool, error) {
	service := &ServiceModel{}
	var exists bool
	if err := dbe.DB.
		Model(&service).
		Select("count(*) > 0").
		Where("name = ? AND secret_key = ?", name, secretKey).
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

func (dbe *DBEngine) CheckServiceByName(name string) (bool, error) {
	service := &ServiceModel{}
	var exists bool
	if err := dbe.DB.
		Model(&service).
		Select("count(*) > 0").
		Where("name = ?", name).
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

func (dbe *DBEngine) GetServiceById(serviceId uint) (*ServiceModel, error) {
	service := &ServiceModel{}
	if err := dbe.DB.
		Where("Id = ?", serviceId).
		Take(&service).
		Error; err != nil {
		return nil, err
	}

	return service, nil
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

func (dbe *DBEngine) GetServiceByName(name string) (*ServiceModel, error) {
	service := &ServiceModel{}
	if err := dbe.DB.
		Where("name = ?", name).
		Take(&service).
		Error; err != nil {
		return nil, err
	}

	return service, nil
}

func (dbe *DBEngine) UpdateRefreshToken(userId uint, refreshToken string) error {
	user, err := dbe.GetUserById(userId)
	if err != nil {
		return err
	}
	if err := dbe.DB.Model(&user).Update("refresh_token", refreshToken).Error; err != nil {
		return err
	}
	return nil
}

func (dbe *DBEngine) UpdateServiceRefreshToken(serviceId uint, refreshToken string) error {
	service, err := dbe.GetServiceById(serviceId)
	if err != nil {
		return err
	}
	if err := dbe.DB.Model(&service).Update("refresh_token", refreshToken).Error; err != nil {
		return err
	}
	return nil
}

func (dbe *DBEngine) CheckUserInService(userId uint, serviceUsername string, serviceId uint) (bool, error) {
	relation := &UserServiceRelation{}
	var exists bool
	if err := dbe.DB.
		Model(&relation).
		Select("count(*) > 0").
		Where("user_id = ? AND service_username = ? AND service_id = ?", userId, serviceUsername, serviceId).
		Find(&exists).
		Error; err != nil {
		return false, err
	}

	return exists, nil
}
