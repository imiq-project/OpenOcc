package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // register "pgx" with database/sql

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// OpenSQLPool opens a single *sql.DB pool through pgx. The pool is shared by
// golang-migrate and GORM so both operate on one connection lifecycle.
func OpenSQLPool(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("db.Ping: %w", err)
	}
	log.Println("Database pool opened (pgx)")
	return db, nil
}

// InitGORM wraps an already-opened *sql.DB with GORM. Migrations are expected
// to have run beforehand — GORM is used only for queries, never for schema.
func InitGORM(sqlDB *sql.DB) *gorm.DB {
	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{})
	if err != nil {
		log.Fatalf("gorm.Open: %v", err)
	}
	log.Println("GORM initialized")
	return db
}

func LoadVehicles(db *gorm.DB) (map[ClientIdType]*Vehicle, error) {
	var list []Vehicle
	if err := db.Find(&list).Error; err != nil {
		return nil, fmt.Errorf("load vehicles: %w", err)
	}
	out := make(map[ClientIdType]*Vehicle, len(list))
	for i := range list {
		v := list[i]
		out[v.Id] = &v
	}
	return out, nil
}

func InsertVehicle(db *gorm.DB, v *Vehicle) error {
	if v.key == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		// TODO: fix
		v.key = "" // EncryptionKey(hex.EncodeToString(buf))
	}
	if err := db.Create(v).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return fmt.Errorf("vehicle %q already exists", v.Id)
		}
		return fmt.Errorf("insert vehicle: %w", err)
	}
	return nil
}

func DeleteVehicle(db *gorm.DB, id ClientIdType) error {
	res := db.Delete(&Vehicle{}, "id = ?", id)
	if res.Error != nil {
		return fmt.Errorf("delete vehicle: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("vehicle %q not found", id)
	}
	return nil
}
