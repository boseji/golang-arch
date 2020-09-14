package main

// Marshaling Example

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
)

var mySigningKey = []byte("Super Secret long Password that works with 86546 number endings")

type customClaims struct {
	SessionID string `json:"session"`
	Email     string `json:"email"`
	jwt.StandardClaims
}

func getToken(session, email string, age time.Duration) (string, error) {
	t := time.Now()
	claims := customClaims{
		SessionID: session,
		Email:     email,
		StandardClaims: jwt.StandardClaims{
			Issuer:    "Test",
			NotBefore: t.Unix(),
			IssuedAt:  t.Unix(),
			ExpiresAt: t.Add(age).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, &claims)
	key := sha512.Sum512(mySigningKey)

	ss, err := token.SignedString(key[:])
	if err != nil {
		return "", fmt.Errorf("couldn't get SignedString in NewWithClaims: %w", err)
	}
	return ss, nil
}

func checkToken(token string) (*customClaims, error) {

	if token == "" {
		return nil, fmt.Errorf("Empty Token")
	}
	tokenAfter, err := jwt.ParseWithClaims(token, &customClaims{},
		func(tokenBefore *jwt.Token) (interface{}, error) {
			if tokenBefore.Method.Alg() != jwt.SigningMethodHS512.Alg() {
				return nil, fmt.Errorf("Wrong Signing method used")
			}
			key := sha512.Sum512(mySigningKey)
			return key[:], nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("Error in checkToken while parsing token: %w", err)
	}

	if !tokenAfter.Valid {
		return nil, fmt.Errorf("Error in checkToken since token is not Valid")
	}

	claims := tokenAfter.Claims.(*customClaims)

	return claims, nil
}

func main() {
	fmt.Print("\n JWT Cookie - with Verification \n\n")

	key := sha512.Sum512(mySigningKey)
	fmt.Printf(" Our Key %q\n", base64.URLEncoding.EncodeToString(key[:]))

	fmt.Println("\n Running Server on :8080")

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/submit", submitHandler)
	http.ListenAndServe(":8080", nil)
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("emailField")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	uid, err := uuid.NewV4()
	if err != nil {
		http.Error(w, "Couldn't session ID", http.StatusInternalServerError)
		log.Println(err)
		return
	}
	session := uid.String()

	code, err := getToken(session, email, 5*time.Second)
	if err != nil {
		http.Error(w, "Couldn't get JWT", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	c := &http.Cookie{
		Name:     "session",
		Value:    code,
		MaxAge:   5,
		HttpOnly: true,
	}

	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie("session")
	if err != nil {
		ck = &http.Cookie{}
	}

	valid := true
	claims, err := checkToken(ck.Value)
	if err != nil {
		valid = false
	}
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>HMAC Cookie Example</title>
	</head>
	<body>
		%s
		<form action="/submit" method="post">
			<input type="email" name="emailField">
			<input type="submit">
		</form>
	</body>
	</html>`

	msg := "Not Logged In"
	if valid {
		msg = "Logged In as " + claims.Email
	}
	cookieAdd := `<p>Cookie Value: ` + ck.Value + `</p>
				  <p>` + msg + `</p>`
	if ck.Value == "" {
		cookieAdd = ""
	}

	io.WriteString(w, fmt.Sprintf(html, cookieAdd))
}
