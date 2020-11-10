package main

import (
	"fmt"
	"io/ioutil"
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
var loginAttempt = map[string]time.Time{}

func main() {
	fmt.Print("\nNinja Level 3 - Hands-On Exercise #3\n\n")

	/*
		For this hands-on exercise:

		- Modify the server from the previous exercise
		- Create an endpoint /oauth/<your provider>/receive
			> Should get the query parameter values state and code
			> State should be used to see if this state has expired
				= time.Now().After()
			> Code should be sent through the config.Exchange function to get a token
			> Create a TokenSource from the token
			> Create an http.Client with the TokenSource
			> Make your call you found in exercise 01 to get a user ID
			> Print out the result from your call
	*/

	herokuOAuth2Config.ClientID = os.Getenv("CLIENT_ID")
	herokuOAuth2Config.ClientSecret = os.Getenv("CLIENT_SECRET")

	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/heroku/login", oHerokuLogin)
	http.HandleFunc("/oauth/heroku/receive", oHerokuReceive)

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
	loginAttempt[uuid] = time.Now().Add(cLogingAttemptExpireDuration)
	return uuid, nil
}

func oHerokuLogin(w http.ResponseWriter, r *http.Request) {
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

func oHerokuReceive(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")
	if code == "" || state == "" {
		log.Println("/oauth/heroku/receive: ERROR Invalid Request Received code-", code)
		log.Println("/oauth/heroku/receive: state-", state)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	t, ok := loginAttempt[state]
	if !ok {
		log.Println("/oauth/heroku/receive: ERROR Invalid State received state-", state)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	delete(loginAttempt, state)

	if time.Now().After(t) {
		log.Println("/oauth/heroku/receive: ERROR Request Expired -", t.String())
		http.Error(w, "Login request expired", http.StatusBadRequest)
		return
	}

	tok, err := herokuOAuth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Println("/oauth/heroku/receive: Error in Oauth2 Exchange-", err)
		http.Error(w, "Oops! Something went wrong.", http.StatusInternalServerError)
		return
	}

	ts := herokuOAuth2Config.TokenSource(r.Context(), tok)

	client := oauth2.NewClient(r.Context(), ts)

	// Fix for Non Standard version requirements in Header of GET request
	//  - Heroku needs the header to be `Accept: application/vnd.heroku+json; version=3`
	//  - However due to Golang http.Request automatic canonization the
	//    'version' becomes "Version" which heroku API does not accept.
	req, _ := http.NewRequest(http.MethodGet, "https://api.heroku.com/account", nil)
	req.Header.Add("Accept", "application/vnd.heroku+json; version=3")
	log.Println(req.Header)
	resp, err := client.Do(req)
	if err != nil {
		log.Println("/oauth/heroku/receive: Error in Get Request via Client-", err)
		http.Error(w, "Oops! Something went wrong.", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("/oauth/heroku/receive: Error in Reading response from Accounts request-", err)
		http.Error(w, "Oops! Something went wrong.", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode > 299 {
		log.Println("/oauth/heroku/receive: Error in Incorrect Response status code-", resp.StatusCode)
		log.Println("/oauth/heroku/receive: Body-", string(bs))
		http.Error(w, "Oops! Something went wrong.", http.StatusInternalServerError)
		return
	}

	log.Println("Data returned : ", string(bs))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
