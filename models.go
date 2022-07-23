package main

import "gorm.io/gorm"

type UserModel struct {
	gorm.Model
	Id       uint `gorm:"primaryKey"`
	Username string
	Password string
}

func (dbe *DBEngine) initTables() error {

	if err := dbe.DB.AutoMigrate(&UserModel{}); err != nil {
		return err
	}

	return nil
}
