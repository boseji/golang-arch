package main

// Marshaling Example

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
)

func main() {
	fmt.Print("\n Encryption and Decryption using AES-OFB\n\n")

	aesKey := make([]byte, 32) // 32 For AES-256
	_, err := io.ReadFull(rand.Reader, aesKey)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("New AES Key: %q\n\n", toBase64(aesKey))

	message := "This is a Super Secret Message that needs to be transmitted safely. Though its big, its essential to maintain secrecy."

	enc, err := encDecAESOFB(aesKey, message)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("Encrypted: %q\n\n", toBase64(enc))

	dec, err := encDecAESOFB(aesKey, string(enc))
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("Decrypted: %q\n\n", string(dec))
}

func encDecAESOFB(key []byte, input string) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error in encDecAESOFB while creating cipher block: %w", err)
	}

	iv := make([]byte, aes.BlockSize)

	crypt := cipher.NewOFB(b, iv)

	var buff bytes.Buffer

	sw := &cipher.StreamWriter{
		S: crypt,
		W: &buff,
	}

	bReader := bytes.NewReader([]byte(input))

	_, err = io.Copy(sw, bReader)
	if err != nil {
		return nil, fmt.Errorf("Error in encDecAESOFB while writing to Stream: %w", err)
	}

	output := buff.Bytes()
	return output, nil
}

func toBase64(input []byte) string {
	return base64.URLEncoding.EncodeToString(input)
}

func fromBase64(input string) ([]byte, error) {
	bs, err := base64.URLEncoding.DecodeString(input)
	if err != nil {
		return nil, fmt.Errorf("Error in fromBase64 while decoding : %w", err)
	}
	return bs, nil
}
