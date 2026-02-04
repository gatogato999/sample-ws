package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/mail"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func HandleBase(res http.ResponseWriter, req *http.Request) {
	UseJson(
		res,
		http.StatusOK,
		map[string]string{
			"msg": `implemented routes: | POST /auth | POST /query/{email}`,
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
			cookie := http.Cookie{
				Name:     "jwt_token",
				Value:    token,
				Path:     "/",                             // optional
				Expires:  time.Now().Add(3 * time.Minute), // optional
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			}
			http.SetCookie(res, &cookie)
			UseJson(
				res,
				http.StatusCreated,
				map[string]string{
					"msg": "logged in sucessfully",
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

func UseJson(res http.ResponseWriter, status int, data any) error {
	res.Header().Set("Content-Type", "application/json; charset=utf-8")
	res.WriteHeader(status)
	if err := json.NewEncoder(res).Encode(data); err != nil {
		return err
	}
	return nil
}
