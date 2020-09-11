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
	fmt.Print("\nJSON Server Encode Decode - Fixed Example\n\n")

	// p2 := person{
	// 	Name: "Radhika",
	// }

	// xp := []person{
	// 	p1,
	// 	p2,
	// }

	// bys, err := json.Marshal(xp)
	// if err != nil {
	// 	log.Panic(err)
	// }

	// fmt.Printf("\nMarshalled: %q \n", string(bys))

	// xp2 := []person{}
	// err = json.Unmarshal(bys, &xp2)
	// if err != nil {
	// 	log.Panic(err)
	// }

	// fmt.Printf("\nBack into Go Datastructure : %v\n\n", xp2)

	http.HandleFunc("/encode", handleEncode)
	http.HandleFunc("/decode", handleDecode)
	http.ListenAndServe(":8080", nil)
}

func handleEncode(w http.ResponseWriter, r *http.Request) {

	p1 := person{
		Name: "Devika",
	}

	err := json.NewEncoder(w).Encode(p1)
	if err != nil {
		log.Println("Error Bad data: ", err)
	}
	// We can Access This using
	// `curl localhost:8080/encode`
}

func handleDecode(w http.ResponseWriter, r *http.Request) {

	var p person

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		log.Println("Error Decode Bad Data: ", err)
	}

	log.Println("Received Person:", p)
	// We can Access This using
	// `curl -XGET -H "Content-type: application/json" -d '{"Name":"Priya"}' localhost:8080/decode`
	//
	// Easy Use: https://curlbuilder.com/
	// To Build this command
}
