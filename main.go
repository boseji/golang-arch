package main

// Marshaling Example

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	fmt.Print("\n AES-CTR File Encryption Example\n\n")

	fr, err := os.Open("test.txt")
	if err != nil {
		log.Fatalln(err)
	}
	defer fr.Close()

	fw, err := os.OpenFile("encrypted.bin", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	defer fw.Close()

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, iv)

	_, err = fw.Write(iv)
	if err != nil {
		log.Fatalln("Error Writing iv", err)
	}

	password := []byte("This is A Super Secret Password")
	key := sha256.Sum256(password)
	keyXb := key[:]

	b, err := aes.NewCipher(keyXb)
	if err != nil {
		log.Fatalln("Error in getting new AES block cipher", err)
	}

	aesctr := cipher.NewCTR(b, iv)
	aesW := &cipher.StreamWriter{
		S: aesctr,
		W: fw,
	}

	_, err = io.Copy(aesW, fr)
	if err != nil {
		log.Fatalln("Error in copying data to stream cipher", err)
	}

	fmt.Print("Encrypted File Written Successfully\n\n")
}
