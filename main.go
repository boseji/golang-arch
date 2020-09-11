package main

// Marshaling Example

import (
	"encoding/json"
	"fmt"
	"log"
)

type person struct {
	Name string
}

func main() {
	fmt.Println("\nJSON Un-Marshalling")

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

	bys, err := json.Marshal(xp)
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("\nMarshalled: %q \n", string(bys))

	xp2 := []person{}
	err = json.Unmarshal(bys, &xp2)
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("\nBack into Go Datastructure : %v\n\n", xp2)
}
