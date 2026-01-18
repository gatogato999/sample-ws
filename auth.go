package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func ProtectRoute(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(
		func(res http.ResponseWriter, req *http.Request) {
			cookie, err := req.Cookie("jwt_token")
			if err != nil {
				if err == http.ErrNoCookie {
					UseJson(
						res,
						http.StatusUnauthorized,
						map[string]string{"error": "Unauthorized"},
					)
					return
				} else {

					UseJson(
						res,
						http.StatusBadRequest,
						map[string]string{"error": "bad request"},
					)
					return
				}
			}

			token := cookie.Value

			if _, err := verifyJwt(token); err != nil {
				UseJson(
					res,
					http.StatusUnauthorized,
					map[string]string{"error": "invalid token"},
				)
				return
			}
			next.ServeHTTP(res, req)
		},
	)
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

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
