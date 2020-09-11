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
	fmt.Print("\nJSON Server Encode - Fixed Example\n\n")

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
	http.HandleFunc("/decode", handleEncode)
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

}
