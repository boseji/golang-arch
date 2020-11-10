package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/heroku"
)

const cNameSessionCookie = "mysession"
const cLogingAttemptExpireDuration = 1 * time.Hour
const password = "This is a Super Secret Key"

type user struct {
	First    string
	password []byte
}

type dataTemp struct {
	User    string
	Message string
}

type mClaims struct {
	SessionID string `json:"session"`
	jwt.StandardClaims
}

type mHerokuData struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

// key is User ID, Value is User Data
var db = map[string]user{}

// Key is SessionID , Value is User ID
var sessions = map[string]string{}

// Siginning Key
var key []byte

var herokuOAuth2Config = &oauth2.Config{
	ClientID:     "",
	ClientSecret: "",
	Endpoint:     heroku.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/heroku/receive",
	Scopes:       []string{"identity"},
}

// Key is UUID of login attempt , Value is expiration for loging attempt
var loginAttempt = map[string]time.Time{}

// Key is Heroku ID , Value is internal User ID
var oauthConn = map[string]string{}

func main() {
	fmt.Print("\nNinja Level 3 - Hands-On Exercise #4\n\n")

	/*
		For this hands-on exercise:

		- Modify the server from the previous exercise
		- Create a new map oauthConnections
			> Key should be user IDs from the oauth provider
			> Value should be user IDs in your own system
		- In endpoint /oauth/<your provider>/receive
			> Extract just the user ID from the result of your call in the previous exercise
				=  This will usually require creating a struct and unmarshalling/decoding json data
			> Get the local user ID from the oauthConnections map
			> If there was no value in the map, set the user ID to a random user ID from your users map
			> Create a session for your user just like how /login does it
				= Good candidate for pulling out into a separate function
			> Redirect the user back to /

		PS: Adding Code from older Ninja Level 2 Exercises
	*/
	k := sha256.Sum256([]byte(password))
	key = k[:]

	herokuOAuth2Config.ClientID = os.Getenv("CLIENT_ID")
	herokuOAuth2Config.ClientSecret = os.Getenv("CLIENT_SECRET")

	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/oauth/heroku/login", oHerokuLogin)
	http.HandleFunc("/oauth/heroku/receive", oHerokuReceive)

	log.Println("Starting Server on Port :8080")
	log.Fatalln(http.ListenAndServe(":8080", nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	errMsg := r.FormValue("errorMsg")
	successMsg := r.FormValue("successMsg")
	tpl := template.Must(template.ParseFiles("index.gohtml"))

	c, err := r.Cookie(cNameSessionCookie)
	if err != nil {
		c = &http.Cookie{
			Name: cNameSessionCookie,
		}
	}

	message := ""
	userid := ""
	sessionID, err := parseToken(c.Value)
	// log.Println("Session: ", sessionID)
	// log.Println(c.Value)
	if err == nil {
		userid = sessions[sessionID]
		first := db[userid].First
		userid = fmt.Sprintf("%s <%s>", first, userid)
		// log.Println("Processing: ", userid)
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

	err = createSession(email, w)
	if err != nil {
		log.Println("Error Signing Session ID")
		log.Println(err)
		msg := url.QueryEscape("Login Failed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	log.Println("Login Successful", email)
	msg := url.QueryEscape("Logged In")
	http.Redirect(w, r, "/?successMsg="+msg, http.StatusSeeOther)
}

func logout(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		log.Printf("Bad Method (logout): %v\n", r.Method)
		msg := url.QueryEscape("Bad Submit Method used")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	c, err := r.Cookie(cNameSessionCookie)
	if err != nil {
		log.Println("/logout :Error No Cookie Present -", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	sid, err := parseToken(c.Value)
	if err != nil {
		log.Println("/logout :Error Invalid Token -", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	user, ok := sessions[sid]
	if !ok {
		log.Println("/logout :Error Session not present or deleted -", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	delete(sessions, sid)
	c.MaxAge = -1
	c.Value = ""
	log.Println("New Sessions -", sessions)
	log.Println("/logout : Logged Out User -", user)
	http.SetCookie(w, c)
	msg := url.QueryEscape("Logged Out")
	http.Redirect(w, r, "/?successMsg="+msg, http.StatusSeeOther)
}

func oHerokuLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Println("/oauth/heroku/login: Error Wrong Method invoked-", r.Method)
		msg := url.QueryEscape("Bad Submit Method used")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	u, err := uuid.NewV4()
	if err != nil {
		log.Println("/oauth/heroku/login: Error Attempt Code-", err)
		msg := url.QueryEscape("Unable to Get data from Heroku")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	uuid := u.String()
	loginAttempt[uuid] = time.Now().Add(cLogingAttemptExpireDuration)

	redirectURL := herokuOAuth2Config.AuthCodeURL(uuid)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func oHerokuReceive(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")
	if code == "" || state == "" {
		log.Println("/oauth/heroku/receive: ERROR Invalid Request Received code-", code)
		log.Println("/oauth/heroku/receive: state-", state)
		msg := url.QueryEscape("Unable to Get data from Heroku")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	expT, ok := loginAttempt[state]
	if !ok {
		log.Println("/oauth/heroku/receive: Error Could not find the Attempt for the state-", state)
		msg := url.QueryEscape("Unable to Get data from Heroku")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	if time.Now().After(expT) {
		log.Println("/oauth/heroku/receive: ERROR Request Expired -", expT.String())
		msg := url.QueryEscape("Login request to Heroku expired")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	tok, err := herokuOAuth2Config.Exchange(r.Context(), code)
	if err != nil {
		log.Println("/oauth/heroku/receive: Error in Oauth2 Exchange-", err)
		msg := url.QueryEscape("Unable to Get data from Heroku")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	delete(loginAttempt, state)

	ts := herokuOAuth2Config.TokenSource(r.Context(), tok)

	herokuData, err := oHerokuAccountAPI(oauth2.NewClient(r.Context(), ts))
	if err != nil {
		log.Println("/oauth/heroku/receive: Error in Get Request via Client-", err)
		msg := url.QueryEscape("Unable to Get data from Heroku")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	// Check if User Already Exists
	userID, ok := oauthConn[herokuData.ID]
	if !ok {
		// if not create One
		u, err := uuid.NewV4()
		if err != nil {
			log.Println("/oauth/heroku/receive: Error in Generating new User ID-", err)
			msg := url.QueryEscape("Unable to Get data from Heroku")
			http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
			return
		}
		userID = u.String()
		oauthConn[herokuData.ID] = userID
		db[userID] = user{
			First: herokuData.Name,
		}
	}

	// Login the User
	err = createSession(userID, w)
	if err != nil {
		log.Println("/oauth/heroku/receive: Error in creating Session-", err)
		msg := url.QueryEscape("Unable to Login via Heroku")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	bs, _ := json.MarshalIndent(herokuData, "", "\n")
	log.Println("Data returned : ", string(bs))
	log.Println("User ID:", userID)
	//msg := url.QueryEscape("Got Heroku Login Data -" + string(bs))
	msg := url.QueryEscape("Logged In via Heroku")
	http.Redirect(w, r, "/?successMsg="+msg, http.StatusSeeOther)
}

func oHerokuAccountAPI(client *http.Client) (*mHerokuData, error) {
	// Fix for Non Standard version requirements in Header of GET request
	//  - Heroku needs the header to be `Accept: application/vnd.heroku+json; version=3`
	//  - However due to Golang http.Request automatic canonization the
	//    'version' becomes "Version" which heroku API does not accept.
	req, err := http.NewRequest(http.MethodGet, "https://api.heroku.com/account", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/vnd.heroku+json; version=3")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	d := json.NewDecoder(resp.Body)

	hd := &mHerokuData{}

	err = d.Decode(hd)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode > 299 {
		return hd, fmt.Errorf("Incorrect Status Code - %d", resp.StatusCode)
	}

	return hd, nil
}

// Since, http.ResponseWriter is an Interface its inherently behaves
// like a pointer. Hence the cookie set here would work when this function
// returns.
func createSession(userID string, w http.ResponseWriter) error {
	u, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("couldn't Create a new UUID in createSession - %w", err)
	}

	sessionID := u.String()

	ss, err := createToken(sessionID)
	if err != nil {
		return fmt.Errorf("couldn't Create a signed token in createSession - %w", err)
	}

	sessions[sessionID] = userID

	c := &http.Cookie{
		Name:     cNameSessionCookie,
		Value:    ss,
		HttpOnly: true,
		MaxAge:   60,
		Path:     "/", // Make Cookie work every where on the website
	}
	http.SetCookie(w, c)

	return nil
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
