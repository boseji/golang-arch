package main

// Marshaling Example

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

var key []byte

func main() {

	// Fill the Key
	for i := 1; i <= sha512.Size; i++ {
		key = append(key, byte(i))
	}

	fmt.Print("\n Hashing Passwords - bcrypt \n\n")
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

	fmt.Print("\nHMAC Message Signing \n\n")

	message := []byte("My Very Secret Message")
	fmt.Printf("\nSecret Message: %q\n\n", string(message))
	sig, err := signMessage(message)
	if err != nil {
		log.Panic(err)
	}
	log.Printf("Signed : %q", base64.StdEncoding.EncodeToString(sig))

	same, err := checkSig(message, sig)
	if err != nil {
		log.Panic(err)
	}

	if !same {
		fmt.Print("\nYour Message has been Tampered With\n\n")
		return
	}

	fmt.Print("\nYour Message is Authentic\n\n")
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

func signMessage(msg []byte) ([]byte, error) {

	// Create the Hasher using a Key
	hash := hmac.New(sha512.New, key)

	_, err := hash.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in signMessage while hashing message: \n %w", err)
	}

	signature := hash.Sum(nil)
	return signature, nil
}

func checkSig(msg, sig []byte) (bool, error) {

	//Create the Hasher using a Key
	newSign, err := signMessage(msg)
	if err != nil {
		return false, err
	}

	same := hmac.Equal(newSign, sig)
	return same, nil
}
