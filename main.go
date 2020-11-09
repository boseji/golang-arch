package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/heroku"
)

const cNameSessionCookie = "session"
const cLogingAttemptExpireDuration = 1 * time.Hour

var herokuOAuth2Config = &oauth2.Config{
	ClientID:     "",
	ClientSecret: "",
	Endpoint:     heroku.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/heroku/receive",
	Scopes:       []string{"identity"},
}

// Key is UUID of login attempt , Value is expiration for loging attempt
var loginAttempt = map[string]int64{}

func main() {
	fmt.Print("\nNinja Level 3 - Hands-On Exercise #2\n\n")

	/*
		For this hands-on exercise:

		- Modify the server from Ninja Level 2
		- Create an oauth2.Config for your provider
			> Fill it in with information from hand-on-exercise 1
				= ClientID
				= ClientSecret
				= Endpoints
					AuthURL
					TokenURL
				= RedirectURL
					http://localhost:8080/oauth/<your provider>/receive
				= Scopes
					IF NEEDED
		- Create an endpoint /oauth/<your provider>/login
			> This should be a POST endpoint
			> This should generate a uuid to use as the state value
			> A new map should be used to save the state and the expiration time
				or this login attempt
				= Key is a string state
				= Value is a time.Time expiration time
					One hour in the future is a reasonable time
			> Redirect the user to the oauth2 AuthCodeURL value
		- Modify your / index page to include an oauth login form
			> The form should post to /oauth/<your provider>/login
			> The login form should only have a submit button
		- LET’S TEST OUR CODE!
			Verify that attempting to login sends you to the oauth provider’s
			login page and approving sends you back to
			/oauth/<your provider>/receive
				You do not have this endpoint yet, if you are using the
				http.ServeMux, your index page will serve this endpoint

	*/

	herokuOAuth2Config.ClientID = os.Getenv("CLIENT_ID")
	herokuOAuth2Config.ClientSecret = os.Getenv("CLIENT_SECRET")

	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/heroku/login", startHerokuOauth)

	log.Println("Starting Server on Port :8080")
	log.Fatalln(http.ListenAndServe(":8080", nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>OAuth - Ninja Level 3 - Hands-On Exercise #2</title>
	</head>
	<body>
		<form action="/oauth/heroku/login" method="post">
			<input type="submit" value="Login Via Heroku">
		</form>
	</body>
	</html>`)
}

func attemptCode() (string, error) {
	u, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("Error in attemptCode while generating UUID - %w", err)
	}
	uuid := u.String()
	loginAttempt[uuid] = time.Now().Add(cLogingAttemptExpireDuration).Unix()
	return uuid, nil
}

func startHerokuOauth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Println("/oauth/heroku/login: Error Wrong Method invoked-", r.Method)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	uuid, err := attemptCode()
	if err != nil {
		log.Println("/oauth/heroku/login: Error Attempt Code-", err)
		http.Error(w, "Oops! Something went wrong.", http.StatusInternalServerError)
		return
	}

	redirectURL := herokuOAuth2Config.AuthCodeURL(uuid)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}
