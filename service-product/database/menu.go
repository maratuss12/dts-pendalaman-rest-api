package database

import "gorm.io/gorm"

type Menu struct {
	ID       int    `json:"id" gorm:"primary_key"` // Tergenerate otomatis
	Username string `json:"username"`              // Username yang menambahkan product
	MenuName string `json:"menu_name"`
	Price    int    `json:"price"`
} // Untuk add item cukup cantumkan menu_name dan price saja

func (menu *Menu) Insert(db *gorm.DB) error {
	result := db.Create(menu)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func (menu *Menu) GetAll(db *gorm.DB) ([]Menu, error) {
	var menus []Menu
	result := db.Find(&menus) // &menus membuat tabel menus di database
	if result.Error != nil {
		return nil, result.Error
	}

	return menus, nil
}
