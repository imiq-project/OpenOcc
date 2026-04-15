package main

import (
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

//go:embed init.sql
var initSQL string

func InitDB(connStr string) *sql.DB {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}
	if _, err := db.Exec(initSQL); err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}
	log.Println("Database initialized")
	return db
}

func LoadVehicles(db *sql.DB) (map[ClientIdType]*Vehicle, error) {
	rows, err := db.Query("SELECT id, name, lat, lon, key FROM vehicles")
	if err != nil {
		return nil, fmt.Errorf("failed to query vehicles: %w", err)
	}
	defer rows.Close()

	vehicles := make(map[ClientIdType]*Vehicle)
	for rows.Next() {
		v := &Vehicle{}
		if err := rows.Scan(&v.Id, &v.Name, &v.Lat, &v.Lon, &v.key); err != nil {
			return nil, fmt.Errorf("failed to scan vehicle: %w", err)
		}
		vehicles[v.Id] = v
	}
	return vehicles, rows.Err()
}

func InsertVehicle(db *sql.DB, v *Vehicle) error {
	if v.key == "" {
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}
		v.key = hex.EncodeToString(keyBytes)
	}
	_, err := db.Exec(
		"INSERT INTO vehicles (id, name, lat, lon, key) VALUES ($1, $2, $3, $4, $5)",
		v.Id, v.Name, v.Lat, v.Lon, v.key,
	)
	return err
}

func DeleteVehicle(db *sql.DB, id ClientIdType) error {
	result, err := db.Exec("DELETE FROM vehicles WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("vehicle %q not found", id)
	}
	return nil
}
