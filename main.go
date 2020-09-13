package main

// Marshaling Example

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	fmt.Print("\n AES-CTR File Decryption Example\n\n")

	fr, err := os.Open("encrypted.bin")
	if err != nil {
		log.Fatalln(err)
	}
	defer fr.Close()

	fw, err := os.OpenFile("decrypted.txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	defer fw.Close()

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(fr, iv)

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

	fmt.Print("Decrypted File Written Successfully\n\n")
}
