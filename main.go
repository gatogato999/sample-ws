package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// manage secrets
	err := godotenv.Load()
	if err != nil {
		log.Printf("\ncant load .env file: %v", err)
		return
	}

	dbPassword := os.Getenv("DBPASS")
	if dbPassword == "" {
		log.Printf("\nsome secerts arent set")
		return
	}

	dbUser := os.Getenv("DBUSER")
	dbName := os.Getenv("DBNAME")
	dbHost := os.Getenv("DBHOST")
	dbPort := os.Getenv("DBPORT")

	// manage database
	databaseSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		dbUser, dbPassword, dbHost, dbPort, dbName)
	db, err := sql.Open("mysql", databaseSource)
	if err != nil {
		log.Printf("\ncan't open the database : %v", err)
		return
	}
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Printf("\ncan't connect to the database : %v", err)
		return
	}

	// manage http server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(res, "implemented routes:\n POST /register\n")
	})
	mux.HandleFunc("POST /register", handleRegister(db))

	// serve
	fmt.Printf("listening at http://localhost:8080")
	http.ListenAndServe(":8080", mux)
}

func handleRegister(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var u User
		err := json.NewDecoder(req.Body).Decode(&u)
		if err != nil {
			http.Error(res,
				err.Error(),
				http.StatusBadRequest)
			return
		}

		u.HashedPassword, err = HassPassword(u.HashedPassword)
		if err != nil {
			log.Printf("\ncan't generate a password : %v", err)
			res.WriteHeader(http.StatusBadRequest)
			return
		}

		if u.Email == "" {
			log.Printf("\ncan't leave the email field empty")
			res.WriteHeader(http.StatusBadRequest)
			return
		}
		err = InsertUser(db, u)
		if err != nil {
			log.Printf("\ncan't insert a new user : %v", err)
			res.WriteHeader(http.StatusBadRequest)
			return
		}

		res.WriteHeader(http.StatusCreated)
	}
}

func HassPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
