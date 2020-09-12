package main

// Marshaling Example

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
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

type key struct {
	key     []byte
	created time.Time
}

var currentKeyID string

// DB to Store the Keys
var keys = map[string]key{}

func main() {
	fmt.Print("\n Encryption and Decryption using AES-CTR\n\n")

	err := generateKeys()
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("Key Generated Successfully: %q\n\n", toBase64(keys[currentKeyID].key))

	aesKey := keys[currentKeyID].key[:32] // 32 - AES 256
	fmt.Printf("New AES Key: %q\n\n", toBase64(aesKey))

	message := "My secret Message to be sent safely. This is long message but is essential for checking the feasibility of Encryption."
	enc, err := encryptAESCTR(aesKey, message)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("Encrypted : %q\n\n", toBase64(enc))

	dec, err := decryptAESCTR(aesKey, string(enc))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Decrypted : %q\n\n", string(dec))
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
	hash := hmac.New(sha512.New, keys[currentKeyID].key)

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
	signedToken, err := t.SignedString(keys[currentKeyID].key)
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
			return keys[currentKeyID].key, nil
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

func generateKeys() error {
	newKey := make([]byte, sha512.Size)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error in generateKeys failed to read random numbers")
	}

	u, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("Error in generateKeys while getting uuid")
	}

	keyID := u.String()

	keys[keyID] = key{
		key:     newKey,
		created: time.Now(),
	}

	currentKeyID = keyID

	return nil
}

func encryptAESCTR(key []byte, input string) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error in encryptAESCTR while creating the AES Cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)

	crypt := cipher.NewCTR(b, iv)

	var buff bytes.Buffer

	sw := &cipher.StreamWriter{
		S: crypt,
		W: &buff,
	}

	bReader := bytes.NewReader([]byte(input))

	_, err = io.Copy(sw, bReader)
	if err != nil {
		return nil, fmt.Errorf("Error in encryptAESCTR while writing to stream : %w", err)
	}

	return buff.Bytes(), nil
}

func decryptAESCTR(key []byte, input string) ([]byte, error) {
	return encryptAESCTR(key, input)
}

func toBase64(input []byte) string {
	return base64.URLEncoding.EncodeToString(input)
}

func fromBase64(input string) ([]byte, error) {
	bs, err := base64.URLEncoding.DecodeString(input)
	if err != nil {
		return nil, fmt.Errorf("Error in fromBase64 while decoding : %w", err)
	}
	return bs, nil
}
