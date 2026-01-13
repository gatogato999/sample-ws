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
``` go get tidy```

## To-Implement

- [x] use .env to store secrets (instead fo hardcoding it)
- [x] check connection to the database
- [x] make functions to deal with the database.
 - [x] insert a user to the database
 - [x] get all users.
 - [x] get a user by email (protected with a token)
- [x] make the http server
- [x] make "/auth" route : send{username, password}, and return JWT token 
 - [x]  users email and password should match stored ones.
 - [x] create a jwt and send it to the user.
- [x] make "/query" route : send {email(as route parm), token}, and return all information
 - [x] create a protected route 
 - [x] get a body request from the user 
 - [x] verify the token and in the body
 - [x] send user info to the specified user.
- [ ] modularize the app
- [ ] graceful shutdown for the db connection and the server.
- [ ] add more accurate status code and error handling
