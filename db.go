package main

import (
	"database/sql"
	"errors"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	ID             int64  `db:"id"              json:"id"`
	FirstName      string `db:"first_name"      json:"firstName"`
	LastName       string `db:"last_name"       json:"lastName"`
	Email          string `db:"email"           json:"email"`
	HashedPassword string `db:"hashed_password" json:"hashed_password"`
	Phone          string `db:"phone"           json:"phone"`
	Age            int    `db:"age"             json:"age"`
	Job            string `db:"job"             json:"job"`
}

func DbInit(db *sql.DB) error {
	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
		first_name VARCHAR(50) NOT NULL,
		last_name VARCHAR(50) NOT NULL,
		email VARCHAR(100) NOT NULL UNIQUE,
		hashed_password VARCHAR(255) NOT NULL,
		phone VARCHAR(30),
		age INT,
		job VARCHAR(150)
	);`

	_, err := db.Exec(createTable)
	if err != nil {
		log.Printf("\ncant create table users : %v", err)
		return err
	}

	return nil
}

func EmailExists(db *sql.DB, email string) error {
	var temp string
	err := db.QueryRow(`select email from users where email = ?  LIMIT 1;`, email).Scan(&temp)
	return err
}

func UserExists(db *sql.DB, email string, password string) (bool, error) {
	if email == "" || password == "" {
		err := errors.New("empty email or password")
		return false, err
	}

	var hPass string

	err := db.QueryRow(`select hashed_password from users where email = ?  LIMIT 1;`,
		email).Scan(&hPass)

	if CheckPasswordHash(password, hPass) {
		return true, nil
	} else {
	}

	if errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err != nil {
		return false, err
	}

	return false, nil
}

func InsertUser(db *sql.DB, user User) error {
	insertUser := `INSERT INTO users (first_name, last_name, email, hashed_password, phone, age, job) 
			 VALUES (?, ?, ?, ?, ?, ?, ?)`

	insertionResult, err := db.Exec(insertUser, user.FirstName, user.LastName, user.Email,
		user.HashedPassword, user.Phone, user.Age, user.Job)
	if err != nil {
		return err
	}
	rows, err := insertionResult.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		log.Printf("expected to affect 1 row, affected %d", rows)
	}
	return nil
}

func GetUserByEmail(db *sql.DB, email string) (User, error) {
	var u User
	err := db.QueryRow(
		`SELECT * FROM users WHERE email = ? LIMIT 1; `,
		email,
	).Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.HashedPassword, &u.Phone, &u.Age, &u.Job)
	if err != nil {
		return User{}, err
	}

	return u, nil
}

func GetAllUsers(db *sql.DB, email string) ([]User, error) {
	rows, err := db.Query(`select * from users `)
	if err != nil {
		return []User{}, err
	}

	defer rows.Close()

	var users []User

	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email,
			&u.HashedPassword, &u.Phone, &u.Age, &u.Job); err != nil {
			log.Printf("\ncan't copy value to user struct : %v", err)
		}
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		return []User{}, err
	}

	return users, nil
}
