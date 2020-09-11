package main

// Marshaling Example

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type person struct {
	Name string
}

func main() {
	fmt.Print("\nJSON Server Encode Decode (Slice) - Fixed Example {Ninja 1 HandsOn 1,2}\n\n")

	http.HandleFunc("/encode", handleEncode)
	http.HandleFunc("/decode", handleDecode)
	http.ListenAndServe(":8080", nil)
}

func handleEncode(w http.ResponseWriter, r *http.Request) {

	p1 := person{
		Name: "Devika",
	}
	p2 := person{
		Name: "Radhika",
	}

	xp := []person{
		p1,
		p2,
	}

	err := json.NewEncoder(w).Encode(xp)
	if err != nil {
		log.Println("Error Bad data: ", err)
	}
	// We can Access This using
	// `curl localhost:8080/encode`
}

func handleDecode(w http.ResponseWriter, r *http.Request) {

	//var p person
	xp2 := []person{}

	err := json.NewDecoder(r.Body).Decode(&xp2)
	if err != nil {
		log.Println("Error Decode Bad Data: ", err)
		return
	}

	log.Println("Received Persons:", xp2)
	// We can Access This using
	// `curl -XGET -H "Content-type: application/json" -d '[{"Name":"Priya"}]' localhost:8080/decode`
	//
	// Easy Use: https://curlbuilder.com/
	// To Build this command
}
