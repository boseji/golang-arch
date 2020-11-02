package main

import (
	"crypto/sha256"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	First    string
	password []byte
}

type dataTemp struct {
	User    string
	Message string
}

var db = map[string]user{}
var sessions = map[string]string{}

const password = "This is a Super Secret Key"

var key []byte

func main() {
	fmt.Print("\nNinja Level 2 - Hands-On Exercise 6\n\n")
	/*
		For this hands-on exercise:

		- Modify the server from the previous exercise
		- Modify createToken and parseToken to use JWT
			= Create a custom claims type that embeds jwt.StandardClaims
			= The custom claims type should have the session id in it
			= Make sure to set the ExpiresAt field with a time limit
				time.Now().......
			= Use an HMAC signing method
			= Make sure to check if the token is valid in the parseToken endpoint
		- Question
			- will we still need our sessions table / database?
			- YES!
	*/
	k := sha256.Sum256([]byte(password))
	key = k[:]

	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)

	fmt.Print("Starting Server on :8080\n\n")
	log.Fatalln(http.ListenAndServe(":8080", nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	errMsg := r.FormValue("errorMsg")
	successMsg := r.FormValue("successMsg")
	tpl := template.Must(template.ParseFiles("index.gohtml"))

	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	message := ""
	userid := ""
	sessionID, err := parseToken(c.Value)
	if err == nil {
		userid = sessions[sessionID]
		first := db[userid].First
		userid = fmt.Sprintf("%s <%s>", first, userid)
	}

	if errMsg != "" {
		message = message + "Error - " + errMsg
	}
	if successMsg != "" {
		message = message + successMsg + " - Success"
	}

	tpl.Execute(w, dataTemp{
		User:    userid,
		Message: message,
	})
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("Bad Method (register): %v\n", r.Method)
		msg := url.QueryEscape("Bad Submit Method used")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	first := r.FormValue("first")

	email := r.FormValue("emailField")
	if email == "" {
		log.Println("Email Empty")
		msg := url.QueryEscape("Email needed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	pass := r.FormValue("passField")
	if pass == "" {
		log.Println("Password Empty")
		msg := url.QueryEscape("Password needed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[email]; ok {
		log.Println("User Already exists - email -", email)
		msg := url.QueryEscape("Failed to Register due to Internal Server Error")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	pw, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		msg := url.QueryEscape("Failed to Register due to Internal Server Error")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	db[email] = user{
		First:    first,
		password: pw,
	}

	msg := "Created User -"
	log.Println(msg, email)
	msg = url.QueryEscape("Registered")
	http.Redirect(w, r, "/?successMsg="+msg, http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("Bad Method (login): %v\n", r.Method)
		msg := url.QueryEscape("Bad Submit Method used")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	email := r.FormValue("emailField")
	if email == "" {
		log.Println("Email Empty (login)")
		msg := url.QueryEscape("Email needed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	pass := r.FormValue("passField")
	if pass == "" {
		log.Println("Password Empty (login)")
		msg := url.QueryEscape("Password needed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	oldPass, ok := db[email]
	if !ok {
		log.Println("Error User does not exists for -", email)
		msg := url.QueryEscape("Login Failed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword(oldPass.password, []byte(pass))
	if err != nil {
		log.Println("Incorrect Passwords -", email)
		msg := url.QueryEscape("Login Failed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	if !ok {
		log.Println("User Does not Exist -", email)
		msg := url.QueryEscape("Login Failed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	u, err := uuid.NewV4()
	if err != nil {
		log.Println("Error generating Session ID")
		log.Println(err)
		msg := url.QueryEscape("Login Failed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}
	sessionID := u.String()

	ss, err := createToken(sessionID)
	if err != nil {
		log.Println("Error Signing Session ID")
		log.Println(err)
		msg := url.QueryEscape("Login Failed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	sessions[sessionID] = email
	c := &http.Cookie{
		Name:     "session",
		Value:    ss,
		HttpOnly: true,
		MaxAge:   60,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, c)

	log.Println("Login Successful", email)
	msg := url.QueryEscape("Logged In")
	http.Redirect(w, r, "/?successMsg="+msg, http.StatusSeeOther)
}

type mClaims struct {
	SessionID string `json:"session"`
	jwt.StandardClaims
}

func createToken(sessionID string) (string, error) {

	claims := mClaims{
		SessionID: sessionID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(1 * time.Minute).Unix(),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)

	ss, err := t.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken while signing JWT: %w", err)
	}

	return ss, nil
}

func parseToken(token string) (string, error) {

	t, err := jwt.ParseWithClaims(token, &mClaims{},
		func(tok *jwt.Token) (interface{}, error) {
			if tok.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("Error in Siging Algorithm used")
			}
			return key, nil
		})

	if err != nil || !t.Valid {
		return "", fmt.Errorf("Error in parseToken when parsing : %w", err)
	}

	v, ok := t.Claims.(*mClaims)
	if !ok {
		return "", fmt.Errorf("Incorrect Claims Type")
	}

	return v.SessionID, nil
}
