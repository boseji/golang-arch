package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	fmt.Print("\nNinja Level 2 - Hands-On Exercise 1\n\n")
	/*
		Create a server with two endpoints

			Endpoint / should display a webpage with a register form on it
				This form should take in at least a username and password
				It should post to /register

			Endpoint /register should save the username and password in a map
				The password should be securely stored using bcrypt
				Redirect the user back to endpoint / afterwards
	*/
	http.HandleFunc("/", root)
	http.HandleFunc("/register", register)

	fmt.Print("Starting Server on :8080\n\n")
	log.Fatalln(http.ListenAndServe(":8080", nil))
}

var store = map[string][]byte{}

func root(w http.ResponseWriter, r *http.Request) {
	tpl := template.Must(template.ParseFiles("index.gohtml"))
	tpl.Execute(w, nil)
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Printf("Bad Method : %v\n", r.Method)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("emailField")
	if email == "" {
		log.Println("Email Empty")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	pass := r.FormValue("passField")
	if email == "" {
		log.Println("Password Empty")
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
		http.Error(w, "Failed to Login", http.StatusInternalServerError)
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
