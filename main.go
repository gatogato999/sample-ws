package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
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
		log.Fatal("\nsome secerts arent set")
		return
	}

	dbUser := os.Getenv("DBUSER")
	dbName := os.Getenv("DBNAME")
	dbHost := os.Getenv("DBHOST")
	dbPort := os.Getenv("DBPORT")

	// manage database connection
	databaseSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s",
		dbUser, dbPassword, dbHost, dbPort, dbName)
	db, err := sql.Open("mysql", databaseSource)
	if err != nil {
		log.Fatal(err)
		return
	}

	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Printf("\ncan't connect to the database : %v", err)
		return
	}

	// manage http server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		useJson(
			res,
			http.StatusOK,
			map[string]string{
				"msg": `implemented routes:
				POST /register
				GET /users
				POST /auth
				POST /query/{email}`,
			},
		)
	})
	mux.HandleFunc("POST /register", handleRegister(db))
	mux.HandleFunc("GET /users", handleGetAllUsers(db))
	mux.HandleFunc("POST /auth", handleLogin(db))
	mux.HandleFunc("POST /query/{email}", handleQuery(db))

	// serve
	fmt.Printf("listening at http://localhost:8080")
	http.ListenAndServe(":8080", mux)
}

func useJson(res http.ResponseWriter, status int, data any) error {
	res.Header().Set("Content-Type", "application/json; charset=utf-8")
	res.WriteHeader(status)
	if err := json.NewEncoder(res).Encode(data); err != nil {
		log.Printf("encoding error : %v", err)
		return err
	}
	return nil
}

func handleQuery(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		token := req.Header.Get("Authorization")
		pathParmValue := req.PathValue("email")
		if pathParmValue == "" {
			// http.Error(res, "empty query parameter; insert an email", http.StatusBadRequest)
			useJson(
				res,
				http.StatusBadRequest,
				map[string]string{"error": "empty query parameter; insert an email"},
			)
			return
		}
		_, err := mail.ParseAddress(pathParmValue)
		if err != nil {
			// http.Error(res, "invalid email", http.StatusBadRequest)
			useJson(res, http.StatusBadRequest, map[string]string{"error": "invalid email"})
			return
		}
		// verify token Bearer
		token = strings.TrimPrefix(token, "Bearer ")
		if _, err := verifyJwt(token); err != nil {
			// http.Error(res, "invalid token", http.StatusUnauthorized)
			useJson(res, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}

		// get user
		u, err := GetUserByEmail(db, pathParmValue)
		if err != nil {
			log.Println("\ndatabase error : ", err)
			// http.Error(
			// 	res,
			// 	"can't get user form the database",
			// 	http.StatusInternalServerError,
			// )
			useJson(
				res,
				http.StatusInternalServerError,
				map[string]string{"error": fmt.Sprint("db error : ", err)},
			)
		} else {
			// res.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(res).Encode(u); err != nil {
				http.Error(res, "\nfailed to encode users", http.StatusInternalServerError)
				useJson(res, http.StatusInternalServerError, map[string]string{"error": fmt.Sprint("encoding failed : ", err)})
			}
		}
	}
}

func verifyJwt(tokenString string) (*jwt.RegisteredClaims, error) {
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))

	tkn, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected method : %v", t.Header["alg"])
			}
			return jwtSecret, nil
		},
	)
	if err != nil {
		return nil, err
	}
	if !tkn.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := tkn.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, errors.New("invalid claims type")
	}
	return claims, nil
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
			useJson(res, http.StatusBadRequest, map[string]string{"error": "can't handle request"})
			return
		}
		exist, err := UserExists(db, logginRequest.Email, logginRequest.HashedPassword)
		if exist {
			jwtSecret := []byte(os.Getenv("JWT_SECRET"))
			if string(jwtSecret) == "" {
				log.Fatal("\nsome secerts aren't set")
				useJson(
					res,
					http.StatusInternalServerError,
					map[string]string{"error": "server config error"},
				)
				return
			}
			token, err := createJwt(logginRequest.Email, jwtSecret)
			if err != nil {
				useJson(
					res,
					http.StatusInternalServerError,
					map[string]string{"error": "token creation error"},
				)
				return
			}
			useJson(
				res,
				http.StatusCreated,
				map[string]string{
					"msg":   "logged in sucessfully",
					"token": token,
				},
			)
			return
		}
		if err != nil {
			log.Printf("%v", err)
			useJson(res,
				http.StatusNotFound,
				map[string]string{"error": "invalid email or password"})
			return
		}
		if !exist {
			useJson(
				res,
				http.StatusNotFound,
				map[string]string{"error": "invalid email or password"},
			)
		}
	}
}

func createJwt(email string, secret []byte) (string, error) {
	claims := jwt.MapClaims{
		"sub":   email,
		"email": email,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func handleGetAllUsers(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var u User
		err := json.NewDecoder(req.Body).Decode(&u)
		if err != nil {
			log.Printf("\n%v", err)
			useJson(res, http.StatusBadRequest, map[string]string{"error": "can't get body"})
			return
		}

		_, err = mail.ParseAddress(u.Email)
		if err != nil {
			useJson(res, http.StatusBadRequest, map[string]string{"error": "invalid email"})
			return
		}

		users, err := GetAllUsers(db, u.Email)
		if err != nil {
			useJson(
				res,
				http.StatusInternalServerError,
				map[string]string{"error": fmt.Sprint("database error", err)},
			)
			return
		}
		useJson(res, http.StatusOK, users)
	}
}

func handleRegister(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var u User
		err := json.NewDecoder(req.Body).Decode(&u)
		if err != nil {
			useJson(res, http.StatusBadRequest, map[string]string{"error": "bad request body"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(u.HashedPassword), 14)
		if err != nil {
			useJson(
				res,
				http.StatusInternalServerError,
				map[string]string{"error": "user creation error"},
			)
			return
		}

		u.HashedPassword = string(hash)

		_, err = mail.ParseAddress(u.Email)
		if err != nil {
			useJson(res, http.StatusBadRequest, map[string]string{"error": "invalid email"})
			return
		}

		err = EmailExists(db, u.Email)
		if err == nil {
			useJson(res, http.StatusBadRequest, map[string]string{"error": " already used email"})
			return
		}
		err = InsertUser(db, u)
		if err != nil {
			useJson(
				res,
				http.StatusInternalServerError,
				map[string]string{"error": "database error"},
			)
			return
		}
		useJson(res, http.StatusCreated, map[string]string{"msg": "new user created"})
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
