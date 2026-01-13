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
		fmt.Fprintf(res, "implemented routes:\n POST /register\n GET /users")
	})
	mux.HandleFunc("POST /register", handleRegister(db))
	mux.HandleFunc("GET /users", handleGetAllUsers(db))
	mux.HandleFunc("POST /auth", handleLogin(db))

	// serve
	fmt.Printf("listening at http://localhost:8080")
	http.ListenAndServe(":8080", mux)
}

func handleLogin(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		type LoginRequest struct {
			Email          string `db:"email"           json:"email"`
			HashedPassword string `db:"hashed_password" json:"hashed_password"`
		}

		var logginRequest LoginRequest
		decoder := json.NewDecoder(req.Body)
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&logginRequest)
		if err != nil {
			http.Error(res,
				" invalid json body",
				http.StatusBadRequest)
			return
		}
		exist, err := UserExists(db, logginRequest.Email, logginRequest.HashedPassword)
		if exist {
			res.WriteHeader(http.StatusAccepted)
			json.NewEncoder(res).Encode(map[string]string{"msg": "logged in sucessfully"})
		}
		if err != nil {
			log.Printf("\n%v\n", err)
			http.Error(res,
				"\n bad request body",
				http.StatusBadRequest)
			return
		}
		if !exist {
			res.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(res).Encode(map[string]string{"msg": "invalid email or password"})

		}
		// res.Header().Set("Content-Type", "application/json")
	}
}

func handleGetAllUsers(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var u User
		err := json.NewDecoder(req.Body).Decode(&u)
		if err != nil {
			log.Printf("\n%v\n", err)
			http.Error(res,
				"\n can't get email from request body",
				http.StatusBadRequest)
			return
		}
		if u.Email == "" {
			http.Error(
				res,
				"\nwrong body ",
				http.StatusInternalServerError,
			)
			return

		}
		users, err := GetAllUsers(db, u.Email)
		if err != nil {
			http.Error(
				res,
				"\nfailed to get users from the database",
				http.StatusInternalServerError,
			)
			return
		}
		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(res).Encode(users); err != nil {
			http.Error(res, "\nfailed to encode users", http.StatusInternalServerError)
		}
	}
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
		hash, _ := bcrypt.GenerateFromPassword([]byte(u.HashedPassword), 14)

		u.HashedPassword = string(hash)

		if u.Email == "" {
			res.WriteHeader(http.StatusBadRequest)
			return
		}
		err = InsertUser(db, u)
		if err != nil {
			res.WriteHeader(http.StatusBadRequest)
			return
		}

		res.Header().Set("Content-Type", "application/json")
		res.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(res).Encode(map[string]string{"msg": "new user created"}); err != nil {
			http.Error(res, "\nfailed to encode ", http.StatusInternalServerError)
		}
	}
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
