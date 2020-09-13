package main

// Marshaling Example

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	fmt.Print("\n SHA256 File Hashing\n\n")

	f, err := os.Open("test.txt")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		log.Fatalln("Error in io.Copy", err)
	}

	result := h.Sum(nil)
	fmt.Printf("Hashed Result %x\n", result)
	fmt.Println("\n The same can be replicated using the command")
	fmt.Print("  'shasum -a 256 test.txt'")
	fmt.Print("\n\n")
}
