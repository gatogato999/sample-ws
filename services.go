package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

func HandleBase(res http.ResponseWriter, req *http.Request) {
	UseJson(
		res,
		http.StatusOK,
		map[string]string{
			"msg": `implemented routes: POST /register GET /users POST /auth POST /query/{email}`,
		},
	)
}

func HandleQuery(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		pathParmValue := req.PathValue("email")
		if pathParmValue == "" {
			UseJson(
				res,
				http.StatusBadRequest,
				map[string]string{"error": "empty query parameter; insert an email"},
			)
			return
		}
		_, err := mail.ParseAddress(pathParmValue)
		if err != nil {
			UseJson(res, http.StatusBadRequest, map[string]string{"error": "invalid email"})
			return
		}

		// get user
		u, err := GetUserByEmail(db, pathParmValue)
		if err != nil {
			UseJson(
				res,
				http.StatusNotFound,
				map[string]string{"error": "not found"},
			)
		} else {
			UseJson(res, http.StatusFound, u)
		}
	}
}

func HandleLogin(db *sql.DB) http.HandlerFunc {
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
			UseJson(res, http.StatusBadRequest, map[string]string{"error": "can't handle request"})
			return
		}
		exist, err := UserExists(db, logginRequest.Email, logginRequest.HashedPassword)
		if exist {
			jwtSecret := []byte(os.Getenv("JWT_SECRET"))
			if string(jwtSecret) == "" {
				log.Fatal("\nsome secerts aren't set")
				UseJson(
					res,
					http.StatusInternalServerError,
					map[string]string{"error": "server config error"},
				)
				return
			}
			token, err := createJwt(logginRequest.Email, jwtSecret)
			if err != nil {
				UseJson(
					res,
					http.StatusInternalServerError,
					map[string]string{"error": "token creation error"},
				)
				return
			}
			UseJson(
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
			UseJson(res,
				http.StatusNotFound,
				map[string]string{"error": "invalid email or password"})
			return
		}
		if !exist {
			UseJson(
				res,
				http.StatusNotFound,
				map[string]string{"error": "invalid email or password"},
			)
		}
	}
}

func HandleGetAllUsers(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var u User
		err := json.NewDecoder(req.Body).Decode(&u)
		if err != nil {
			log.Printf("\n%v", err)
			UseJson(res, http.StatusBadRequest, map[string]string{"error": "can't get body"})
			return
		}

		_, err = mail.ParseAddress(u.Email)
		if err != nil {
			UseJson(res, http.StatusBadRequest, map[string]string{"error": "invalid email"})
			return
		}

		type UsersRes struct {
			Users []User `json:"users"`
		}
		users, err := GetAllUsers(db, u.Email)
		if err != nil {
			UseJson(
				res,
				http.StatusInternalServerError,
				map[string]string{"error": fmt.Sprint("database error", err)},
			)
			return
		}
		numberOfUsers := len(users)
		uRes := map[string]any{"users": users, "numberOfUsers": numberOfUsers}
		// UsersRes{Users: users}
		UseJson(res, http.StatusOK, uRes)
	}
}

func HandleRegister(db *sql.DB) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		var u User
		err := json.NewDecoder(req.Body).Decode(&u)
		if err != nil {
			UseJson(res, http.StatusBadRequest, map[string]string{"error": "bad request body"})
			return
		}
		if u.FirstName == "" || u.LastName == "" || u.Phone == "" {
			UseJson(
				res,
				http.StatusBadRequest,
				map[string]string{"error": "u can't let those fields empty"},
			)
			return
		}
		if u.Age < 18 {
			UseJson(
				res,
				http.StatusBadRequest,
				map[string]string{"error": "age can't be less that 18"},
			)
			return
		}
		if len(u.HashedPassword) < 8 {
			UseJson(
				res,
				http.StatusBadRequest,
				map[string]string{"error": "password can'nt be less that 8"},
			)
			return
		}
		if _, err := mail.ParseAddress(u.Email); err != nil || u.Email == "" {
			UseJson(
				res,
				http.StatusBadRequest,
				map[string]string{"error": "invalid email"},
			)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(u.HashedPassword), 14)
		if err != nil {
			UseJson(
				res,
				http.StatusInternalServerError,
				map[string]string{"error": "can't create user"},
			)
			return
		}

		u.HashedPassword = string(hash)

		_, err = mail.ParseAddress(u.Email)
		if err != nil {
			UseJson(res, http.StatusBadRequest, map[string]string{"error": "invalid email"})
			return
		}

		err = EmailExists(db, u.Email)
		if err == nil {
			UseJson(res, http.StatusBadRequest, map[string]string{"error": " already used email"})
			return
		}
		err = InsertUser(db, u)
		if err != nil {
			UseJson(
				res,
				http.StatusInternalServerError,
				map[string]string{"error": "database error"},
			)
			return
		}
		UseJson(res, http.StatusCreated, map[string]string{"msg": "new user created"})
	}
}

func UseJson(res http.ResponseWriter, status int, data any) error {
	res.Header().Set("Content-Type", "application/json; charset=utf-8")
	res.WriteHeader(status)
	if err := json.NewEncoder(res).Encode(data); err != nil {
		return err
	}
	return nil
}
