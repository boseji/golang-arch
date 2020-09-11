package main

// Marshaling Example

import (
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	fmt.Print("\nHashing Passwords - bcrypt\n\n")
	pass := "123456789"
	hash, err := hashPassword(pass)
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("Hashed password: %s\n\n", string(hash))
	err = comparePassword(pass, hash)
	if err != nil {
		log.Fatalln("Not Logged In")
	}
	log.Println("Password Authentication Success!")
}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error in generating hash from password: \n %w", err)
	}
	return bs, err
}

func comparePassword(password string, hashedPassword []byte) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
}
