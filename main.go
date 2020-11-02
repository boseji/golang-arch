package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	fmt.Print("\nNinja Level 2 - Hands-On Exercise 4\n\n")
	/*
		For this hands-on exercise:

		Modify the server from the previous exercise
		- On /login
			- Generate a session id
				- Use a map sessions between session id and username
			- Use createToken with the generated session id
			- Set the token as the value of a session cookie

		- Change login endpoint to redirect the user back to /
		- On /
			- Use parseToken to get the session id
			- Use the sessions map to get the username
			- Display the username in the page if one has been found
				- No username will be displayed if
					- No session cookie set
					- Session cookie validation failed
					- No session in the sessions map to a username
	*/
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)

	fmt.Print("Starting Server on :8080\n\n")
	log.Fatalln(http.ListenAndServe(":8080", nil))
}

var store = map[string][]byte{}
var sessions = map[string]string{}

const key = "This is a Super Secret Key"

func index(w http.ResponseWriter, r *http.Request) {
	errMsg := r.FormValue("errorMsg")
	successMsg := r.FormValue("successMsg")
	tpl := template.Must(template.ParseFiles("index.gohtml"))

	c, err := r.Cookie("session")
	if err != nil {
		c = &http.Cookie{}
	}

	message := ""

	sessionID, err := parseToken(c.Value)
	if err == nil {
		userid, ok := sessions[sessionID]
		if ok {
			message = "Logged In as " + userid + " | "
		}
	}

	if errMsg != "" {
		message = message + "Error - " + errMsg
	}
	if successMsg != "" {
		message = message + successMsg + " - Success"
	}
	tpl.Execute(w, message)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("Bad Method (register): %v\n", r.Method)
		msg := url.QueryEscape("Bad Submit Method used")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

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

	if _, ok := store[email]; ok {
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

	store[email] = pw

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

	oldPass, ok := store[email]
	if !ok {
		log.Println("Error User does not exists for -", email)
		msg := url.QueryEscape("Login Failed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword(oldPass, []byte(pass))
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

func createToken(sessionID string) (string, error) {
	h := hmac.New(sha256.New, []byte(key))

	_, err := h.Write([]byte(sessionID))
	if err != nil {
		return "", fmt.Errorf("Failed to write to hmac in createToken: %w", err)
	}

	code := h.Sum(nil)
	result := base64.URLEncoding.EncodeToString(code) + "|" + sessionID
	return result, nil
}

func parseToken(token string) (string, error) {
	xs := strings.SplitN(token, "|", 2)
	if len(xs) != 2 {
		return "", fmt.Errorf("Error in Token")
	}

	code, err := base64.URLEncoding.DecodeString(xs[0])
	if err != nil {
		return "", fmt.Errorf("Failed decode base64 code in parseToken: %w", err)
	}

	sessionID := xs[1]

	h := hmac.New(sha256.New, []byte(key))
	_, err = h.Write([]byte(sessionID))
	if err != nil {
		return "", fmt.Errorf("Failed to write to hmac in parseToken: %w", err)
	}

	v := h.Sum(nil)

	equal := hmac.Equal(code, v)
	if !equal {
		return "", fmt.Errorf("Error in Token or it was tampered with")
	}

	return sessionID, nil
}
