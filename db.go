package main

import (
	"database/sql"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	ID             int64  `db:"id"              json:"id"`
	FirstName      string `db:"first_name"      json:"firstName"`
	LastName       string `db:"last_name"       json:"lastName"`
	Email          string `db:"email"           json:"email"`
	HashedPassword string `db:"hashed_password" json:"-"`
	Phone          string `db:"phone"           json:"phone,omitempty"`
	Age            int    `db:"age"             json:"age,omitempty"`
	Job            string `db:"job"             json:"job,omitempty"`
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
		log.Fatal(err)
		return err
	}
	if rows != 1 {
		log.Fatalf("expected to affect 1 row, affected %d", rows)
	}
	return nil
}

func GetUserByEmail(db *sql.DB, email string) (User, error) {
	const getUserByEmailStmt = "SELECT * FROM users WHERE email = ? LIMIT 1; "
	stmt, err := db.Prepare(getUserByEmailStmt)
	if err != nil {
		log.Printf("\ncan't Prepare statement : %v", err)
		return User{}, nil
	}

	defer stmt.Close()

	var u User
	err = stmt.QueryRow(email).Scan(
		&u.ID,
		&u.FirstName,
		&u.LastName,
		&u.Email,
		&u.HashedPassword,
		&u.Phone,
		&u.Age,
		&u.Job,
	)

	return u, nil
}

func GetAllUser(db *sql.DB, email string) ([]User, error) {
	rows, err := db.Query("select * from users ")
	if err != nil {
		return []User{}, err
	}

	defer rows.Close()

	var users []User

	for rows.Next() {
		var u User
		if err := rows.Scan(&u); err != nil {
			log.Fatal(err)
			log.Printf("\ncan't Prepare statement : %v", err)
		}
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		return []User{}, err
	}

	return users, nil
}
