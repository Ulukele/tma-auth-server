package main

import "gorm.io/gorm"

type UserModel struct {
	gorm.Model
	Id           uint `gorm:"primaryKey"`
	Username     string
	Password     string
	RefreshToken string
}

type ServiceModel struct {
	gorm.Model
	Id           uint `gorm:"primaryKey"`
	Name         string
	SecretKey    string
	RefreshToken string
}

type UserServiceRelation struct {
	Id              uint `gorm:"primaryKey"`
	ServiceModelId  uint
	UserId          uint
	ServiceUsername string
}

func (dbe *DBEngine) initTables() error {

	if err := dbe.DB.AutoMigrate(&UserModel{}); err != nil {
		return err
	}
	if err := dbe.DB.AutoMigrate(&ServiceModel{}); err != nil {
		return err
	}
	if err := dbe.DB.AutoMigrate(&UserServiceRelation{}); err != nil {
		return err
	}

	return nil
}
