# Go Web Server

## Installation 

- install MariaDB 
``` sudo pacman -S mariadb ```
- install go 
``` sudo pacman -S go ```
- make sure the mariadb is running
``` sudo systemctl start mariadb```
- clone the repo
```git clone github.com/gatogato999/sample-ws  ```
- init the go mod 
```go mod init github.com/gatogato999/sample-ws ```
- install the dependincies (mysql-driver, jwt, bcrypt, gotdotenv)
``` go get .```

## To-Implement

- [x] use .env to store secrets (instead fo hardcoding it)
- [x] check connection to the database
- [ ] make functions to deal with the database.
 - [ ] get a user by email
 - [ ] insert a user to the database
- [ ] make the http server
- [ ] make "/auth" route : send{username, password}, and return JWT token 
- [ ] make "/query" route : send {token,email}, and return all information

## Note

- [ ] users info is stored in a mysql (maria) database, retrived by "/query".
- [ ] to modularize the app
- [ ] graceful shutdown for the db connection and the server.
