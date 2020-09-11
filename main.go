package main

// Marshaling Example

import (
	"encoding/base64"
	"fmt"
)

func main() {
	fmt.Print("\nHTTP Basic Authentication - base64\n\n")
	authString := "user:pass"
	enc := base64.StdEncoding.EncodeToString([]byte(authString))
	fmt.Printf("\nBase64 Encoding for %q is %q\n\n", authString, enc)
}
