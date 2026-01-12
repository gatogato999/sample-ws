package main

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("cant load .env file: %v", err)
		os.Exit(1)
	}

	dbPassword := os.Getenv("DBPASS")
	if dbPassword == "" {
		fmt.Printf("some secerts arent set")
		os.Exit(1)
	}

	mysql.EnableCompression(true)
	dbUser := os.Getenv("DBUSER")
	dbName := os.Getenv("DBNAME")
	dbHost := os.Getenv("DBHOST")
	dbPort := os.Getenv("DBPORT")

	databaseSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		dbUser, dbPassword, dbHost, dbPort, dbName)
	fmt.Printf("%s", databaseSource)
	db, err := sql.Open("mysql", databaseSource)
	if err != nil {
		fmt.Printf("can't open the database : %v", err)
		os.Exit(1)
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	defer db.Close()

	er := db.Ping()
	if er != nil {
		fmt.Printf("can't connect to the database : %v", er)
		os.Exit(1)
	}
}
