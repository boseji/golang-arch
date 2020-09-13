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
	fmt.Print("\n HMAC Cookie Example\n\n")

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

	sessionValid := false

	ck, err := r.Cookie("session")
	for err == nil && ck != nil {
		val := ck.Value
		values := strings.Split(val, "|")
		if len(values) != 2 {
			break
		}

		ncode := values[0]

		nemail := values[1]

		if ncode == code && nemail == email {
			sessionValid = true
		}
		break
	}

	http.SetCookie(w, c)
	if !sessionValid {
		io.WriteString(w, "Success")
		return
	}
	io.WriteString(w, "Already Logged In")
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>HMAC Cookie Example</title>
	</head>
	<body>
		<form action="/submit" method="post">
			<input type="email" name="email">
			<input type="submit">
		</form>
	</body>
	</html>`

	io.WriteString(w, html)
}
