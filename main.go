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

	"golang.org/x/crypto/bcrypt"
)

func main() {
	fmt.Print("\nNinja Level 2 - Hands-On Exercise 3\n\n")
	/*
		For this hands-on exercise:
			Modify the server from the previous exercise
			Add a login form to the webpage
				The form should take in a username and password
				The form should post to a /login endpoint
			Add a new endpoint /login
				The endpoint should compare the given credentials with stored
				credentials in the user map
					Make sure to use the bcrypt function to compare the password
			If the credentials match, display a webpage saying login successful
			If the credentials do not match, display a webpage saying login failed
	*/
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)

	fmt.Print("Starting Server on :8080\n\n")
	log.Fatalln(http.ListenAndServe(":8080", nil))
}

var store = map[string][]byte{}

const key = "This is a Super Secret Key"

func index(w http.ResponseWriter, r *http.Request) {
	errMsg := r.FormValue("errorMsg")
	successMsg := r.FormValue("successMsg")
	tpl := template.Must(template.ParseFiles("index.gohtml"))

	message := ""
	if errMsg != "" {
		message = "Error - " + errMsg
	}
	if successMsg != "" {
		message = successMsg + " - Success"
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

	oldPass := []byte{}
	if p, ok := store[email]; ok {
		oldPass = p
	}

	updated := len(oldPass) != 0

	err := bcrypt.CompareHashAndPassword(oldPass, []byte(pass))
	if err != nil && updated {
		log.Println("Changing Passwords -", email)
	}

	olduser := updated && err == nil
	updated = updated && err != nil

	pw, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Println(err)
		msg := url.QueryEscape("Failed to Register due to Internal Server Error")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	store[email] = pw

	msg := "Created User -"
	if updated {
		msg = "Updated User -"
	}
	if olduser {
		msg = "Valid User -"
	}
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

	oldPass := []byte{}
	oldPass, ok := store[email]

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
