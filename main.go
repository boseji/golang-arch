package main

// Marshaling Example

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

func main() {
	fmt.Print("\n HMAC Cookie Example - Correct Validation \n\n")

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/submit", submitHandler)
	http.ListenAndServe(":8080", nil)
}

var password = []byte("my Super Secret Password")

func getCode(data string) (string, error) {
	key := sha256.Sum256(password)

	h := hmac.New(sha256.New, key[:])
	_, err := io.WriteString(h, data)
	if err != nil {
		return "", fmt.Errorf("Error in getCode while writing to digest")
	}

	result := fmt.Sprintf("%x", h.Sum(nil))
	return result, nil
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	code, err := getCode(email)
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		log.Println(err)
		return
	}

	c := &http.Cookie{
		Name:  "session",
		Value: code + "|" + email,
	}

	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie("session")
	if err != nil {
		ck = &http.Cookie{}
	}

	isEqual := true
	xs := strings.SplitN(ck.Value, "|", 2)
	if len(xs) == 2 {
		cCode := xs[0]
		cEmail := xs[1]

		code, _ := getCode(cEmail)

		isEqual = hmac.Equal([]byte(cCode), []byte(code))
	}

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>HMAC Cookie Example</title>
	</head>
	<body>
		%s
		<form action="/submit" method="post">
			<input type="email" name="email">
			<input type="submit">
		</form>
	</body>
	</html>`

	msg := "Not Logged In"
	if isEqual {
		msg = "Logged In"
	}
	cookieAdd := `<p>Cookie Value: ` + ck.Value + `</p>
				  <p>` + msg + `</p>`
	if ck.Value == "" {
		cookieAdd = ""
	}

	io.WriteString(w, fmt.Sprintf(html, cookieAdd))
}
