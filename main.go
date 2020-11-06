package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const password = "This is a Super Secret Key"

var key []byte

var githubOauthConfig = &oauth2.Config{
	ClientID:     "",
	ClientSecret: "",
	Endpoint:     github.Endpoint,
	RedirectURL:  "",
	Scopes:       []string{},
}

type dataTemplate struct {
	User    string
	Message string
}

// key = SessionID and Value = Auth Code from Github
var githubSessions = map[string]string{}

// Key = code and Value= Expiry Time
var githubRequest = map[string]time.Time{}

func main() {
	fmt.Print("\nOAuth2 github - Base page\n\n")
	/*
		Make sure that the Page is able to show
		the Login button and Redirect to Github.
	*/
	k := sha256.Sum256([]byte(password))
	key = k[:]

	githubOauthConfig.ClientID = os.Getenv("CLIENT_ID")
	githubOauthConfig.ClientSecret = os.Getenv("CLIENT_SECRET")

	http.HandleFunc("/", index)
	http.HandleFunc("/oauth2/github/start", startGithubOAuth)
	http.HandleFunc("/oauth2/github/receive", completeGithubOAuth)

	fmt.Print("Starting Server on :8080\n\n")
	log.Fatalln(http.ListenAndServe(":8080", nil))
}

// Generate a Code with Expiry timeout
func generateCode(d time.Duration) (string, time.Time) {
	// Unique code to identify the Request
	code := "0000"
	buf := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, buf)
	if err == nil {
		code = fmt.Sprintf("%x", buf)
	}
	return code, time.Now().Add(d)
}

func index(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles("index.gohtml"))
	err := t.Execute(w, &dataTemplate{})
	if err != nil {
		log.Println("Error in Parsing File: ", err)
		http.Error(w, "Error in Rendering Page", http.StatusInternalServerError)
	}
}

func startGithubOAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.Println("/oauth2/github/start: Incorrect Oauth Call method -", r.Method)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	code, t := generateCode(time.Second * 40)
	// Append the Request
	githubRequest[code] = t

	redirectURL := githubOauthConfig.AuthCodeURL(code)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func completeGithubOAuth(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	timeout, ok := githubRequest[state]
	if !ok {
		log.Println("/oauth2/github/receive: Incorrect Redirect with state-", state)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if timeout.Unix() < time.Now().Unix() {
		log.Println("/oauth2/github/receive: May Have expired -", timeout.String())
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	code := r.FormValue("code")
	if len(code) == 0 {
		log.Println("/oauth2/github/receive: Error Code found to be Zero Value")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		log.Println("/oauth2/github/receive: Error in Token Exchange -", err)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ts := githubOauthConfig.TokenSource(r.Context(), token)

	client := oauth2.NewClient(r.Context(), ts)

	requestBody := strings.NewReader(`{ "query": "query { viewer { id } }" }`)
	resp, err := client.Post("https://api.github.com/graphql",
		"application/json", requestBody)
	if err != nil {
		log.Println("/oauth2/github/receive: Failed to Get Data-", err)
		http.Error(w, "Error in Fetching Data", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	xb, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("/oauth2/github/receive: Failed to Read GithubResponse Data-", err)
		http.Error(w, "Error in Fetching Data", http.StatusInternalServerError)
		return
	}
	log.Println("Response-", string(xb))
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return
}
