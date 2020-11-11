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
	"strings"
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
const cProviderList = "Heroku"
const cProviderHeroku = "Heroku"

type user struct {
	First    string
	password []byte
}

type dataTemp struct {
	User     string
	Message  string
	SignedIn bool
}

type dataPartialTemp struct {
	Name        string
	Email       string
	Age         string
	ID          string
	Provider    string
	ProviderURI string
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
	fmt.Print("\nNinja Level 3 - Hands-On Exercise #6\n\n")

	/*
		For this hands-on exercise:

		- Modify the server from the previous exercise
		- Create endpoint /oauth/<your provider>/register
			= Extract the oauth provider’s user ID from its token
				> Your parseToken function should work
				> Send a user back to / if there is a problem
			= Create an entry in your user map
				> Fill in all information using the submitted form
				> Leave the bcrypted password field blank
			= Create an entry in your oauthConnections map
				> Key will be your provider’s user ID
				> Value will be the new user’s ID
			= Create a session for your user just like how /login and
				/oauth/<your provider>/receive does it
			= Redirect the user back to /
		- Make sure your /login endpoint will not log in anyone if they have no password
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
	http.HandleFunc("/partial-register", partialRegister)
	http.HandleFunc("/oauth/heroku/register", oHerokuRegister)

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

	signed := true
	if userid == "" {
		signed = false
	}

	if errMsg != "" {
		message = message + "Error - " + errMsg
	}
	if successMsg != "" {
		message = message + successMsg + " - Success"
	}

	tpl.Execute(w, dataTemp{
		User:     userid,
		Message:  message,
		SignedIn: signed,
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

	userData, ok := db[email]
	if !ok {
		log.Println("Error User does not exists for -", email)
		msg := url.QueryEscape("Login Failed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	if userData.password == nil || len(userData.password) == 0 {
		log.Println("Error User with no Password or Oauth -", email)
		msg := url.QueryEscape("Login Failed")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword(userData.password, []byte(pass))
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
	//log.Println("New Sessions after Logout -", sessions)
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

	// Check if Provider User Already Exists
	userID, ok := oauthConn[herokuData.ID]
	if !ok {
		// Provider User Does not exist so forward them
		// to Partial-Register
		id := herokuData.ID
		// Create Token using the heroku User ID
		ss, err := createToken(id)
		if err != nil {
			log.Println("/oauth/heroku/receive: couldn't create token for Heroku New User-", err)
			msg := url.QueryEscape("Unable to process your Heroku data")
			http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
			return
		}
		// email := r.FormValue("email")
		// name := r.FormValue("name")
		// age := r.FormValue("age")
		// id := r.FormValue("user")
		// provider := r.FormValue("provider")
		uv := url.Values{}
		uv.Add("email", herokuData.Email)
		uv.Add("name", herokuData.Name)
		uv.Add("user", ss)
		uv.Add("provider", cProviderHeroku)
		http.Redirect(w, r, "/partial-register?"+uv.Encode(), http.StatusSeeOther)
		return
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

func partialRegister(w http.ResponseWriter, r *http.Request) {

	id := r.FormValue("user")
	if id == "" {
		msg := url.QueryEscape("Incorrect request - user ID is invalid")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	if c, _ := r.Cookie(cNameSessionCookie); c != nil {
		msg := url.QueryEscape("Incorrect request - You are already signed-in")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	provider := r.FormValue("provider")
	if provider == "" {
		msg := url.QueryEscape("Incorrect request - provider is invalid")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	if !strings.Contains(cProviderList, provider) {
		log.Println("partialRegister: Invalid Provider Supplied -", provider)
		msg := url.QueryEscape("Incorrect request - provider is invalid")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	_, err := parseToken(id)
	if err != nil {
		log.Println("partialRegister: Error in Parsing Token -", err)
		msg := url.QueryEscape("Incorrect request")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	name := r.FormValue("name")
	age := r.FormValue("age")

	d := dataPartialTemp{
		Name:        name,
		Email:       email,
		Age:         age,
		ID:          id,
		Provider:    provider,
		ProviderURI: strings.ToLower(provider),
	}

	tpl := template.Must(template.ParseFiles("partial-register.gohtml"))
	tpl.Execute(w, d)
}

func oHerokuRegister(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		log.Println("Error Wrong Method invoked in oHerokuRegister -", r.Method)
		msg := url.QueryEscape("Bad Submit Method used")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	ss := r.FormValue("user")
	if ss == "" {
		log.Println("Error empty User in oHerokuRegister")
		msg := url.QueryEscape("Invalid Request")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	id, err := parseToken(ss)
	if err != nil {
		log.Println("Error parseToken in oHerokuRegister -", err)
		msg := url.QueryEscape("Invalid Request")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	email := r.FormValue("emailField")
	if email == "" {
		log.Println("Error empty Email in oHerokuRegister")
		msg := url.QueryEscape("Invalid Request")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[email]; ok {
		log.Println("Error in oHerokuRegister - user already exist for", email)
		msg := url.QueryEscape("Invalid Request")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	name := r.FormValue("first")

	db[email] = user{
		First: name,
	}

	oauthConn[id] = email

	// Login the User
	err = createSession(email, w)
	if err != nil {
		log.Println("Error createSession in oHerokuRegister -", err)
		msg := url.QueryEscape("Unable to Login via Heroku")
		http.Redirect(w, r, "/?errorMsg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("Logged In via Heroku")
	http.Redirect(w, r, "/?successMsg="+msg, http.StatusSeeOther)
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
