package main

// Marshaling Example

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// UserClaims custom claims Structure
type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

// Valid - Implementing the Required Interface for JWT token Claims
func (u *UserClaims) Valid() error {
	if u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has Expired")
	}

	if u.SessionID <= 0 {
		return fmt.Errorf("Invalid Session ID")
	}

	return nil
}

// HMAC Key for JWT and Sign
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

	fmt.Print("\nJWT Token Example\n\n")

	claims := &UserClaims{}
	claims.SessionID = 35
	signedToken, err := createToken(claims)
	if err != nil {
		log.Panic(err)
	}
	log.Println("Original Claims:", claims)
	log.Println("Signed Token:", signedToken)
	fmt.Print("\n Token has parts separated by '.'\n\n")

	respClaims, err := parseToken(signedToken)
	if err != nil {
		log.Panic(err)
	}
	log.Println("Varified Token Claims:", respClaims)
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

func createToken(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := t.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing token : %w", err)
	}
	return signedToken, nil
}

func parseToken(signedToken string) (*UserClaims, error) {

	// Empty Claim is passed since its not used
	// - This Verification of Signing Method to get the Specific Key
	// - Some times the 'keyID' is also fetched from the token
	// - Token `t` using in the callback is a non-verified token
	//   use it with caution
	t, err := jwt.ParseWithClaims(signedToken, &UserClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
				return nil, fmt.Errorf("Error Invalid Signing Method")
			}
			return key, nil
		})

	if err != nil {
		return nil, fmt.Errorf("Error in parseToken while verifying the token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in parseToken since token is not valid")
	}

	claims := t.Claims.(*UserClaims)
	return claims, nil
}
