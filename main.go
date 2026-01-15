package main

import (
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	db, err := GainAccessToDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/", HandleBase)
	mux.HandleFunc("POST /register", HandleRegister(db))
	mux.HandleFunc("POST /users", ProtectRoute(HandleGetAllUsers(db)))
	mux.HandleFunc("POST /auth", HandleLogin(db))
	mux.HandleFunc("POST /query/{email}", ProtectRoute(HandleQuery(db)))

	fmt.Printf("listening at http://localhost:8080")
	http.ListenAndServe(":8080", withCors(mux))
}

func withCors(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(res http.ResponseWriter, req *http.Request) {
			res.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
			res.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			res.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			res.Header().Set("Content-Security-Policy",
				"script-src 'self' 'unsafe-eval' 'unsafe-inline'")
			if req.Method == http.MethodOptions {
				res.WriteHeader(http.StatusOK)
				return
			}
			next.ServeHTTP(res, req)
		},
	)
}
