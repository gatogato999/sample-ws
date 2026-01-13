package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
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
		log.Printf("\nsome secerts arent set")
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
		fmt.Fprintf(
			res,
			"implemented routes:\n POST /register\n GET /users\n POST /auth\n POST /query/{email}",
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

func handleQuery(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		token := req.Header.Get("Authorization")
		if token == "" {
			http.Error(res, "empty Authorization header", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(token, "Bearer ") {
			http.Error(res, "invalid Authorization header", http.StatusBadRequest)
			return
		}
		pathParmValue := req.PathValue("email")
		if pathParmValue == "" {
			http.Error(res, "empty query parameter; insert an email", http.StatusBadRequest)
			return
		}
		if !strings.Contains(pathParmValue, "@") {

			http.Error(res, "invalid email", http.StatusBadRequest)
			return
		}
		// fmt.Fprintf(res, "\nemail : %s\n token : %s\n", pathParmValue, token)
		// res.WriteHeader(http.StatusAccepted)
		// verify token Bearer
		token = strings.TrimPrefix(token, "Bearer ")
		if _, err := verifyJwt(token); err != nil {
			http.Error(res, "invalid token", http.StatusUnauthorized)
			return
		}

		// get user
		u, err := GetUserByEmail(db, pathParmValue)
		if err != nil {
			log.Println("\ndatabase error : ", err)
			http.Error(
				res,
				"can't get user form the database",
				http.StatusInternalServerError,
			)
		} else {
			// fmt.Fprintf(res, "id: %d\nfName: %s\nlName: %s\nemail: %s\npass: %s\nphone: %s\nage: %d\njob: %s\n",
			// 	u.ID, u.FirstName, u.LastName, u.Email, u.HashedPassword, u.Phone, u.Age, u.Job)

			res.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(res).Encode(u); err != nil {
				http.Error(res, "\nfailed to encode users", http.StatusInternalServerError)
			}
		}
	}
}

func AuthMeddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(res http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(res, req)
		},
	)
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
			http.Error(res,
				" invalid json body",
				http.StatusBadRequest)
			return
		}
		exist, err := UserExists(db, logginRequest.Email, logginRequest.HashedPassword)
		if exist {
			// jwt
			jwtSecret := []byte(os.Getenv("JWT_SECRET"))
			if string(jwtSecret) == "" {
				log.Printf("\nsome secerts aren't set")
				return
			}
			token, err := createJwt(logginRequest.Email, jwtSecret)
			if err != nil {
				http.Error(res, "could not create token", http.StatusInternalServerError)
				return
			}
			res.Header().Set("Content-Type", "application/json")
			json.NewEncoder(res).
				Encode(map[string]string{"token": token, "msg": "logged in sucessfully"})
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
