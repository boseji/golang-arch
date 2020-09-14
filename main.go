package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	fmt.Print("\nNinja Level 2 - Hands-On Exercise 2\n\n")
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
