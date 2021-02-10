package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	// Create a Input Stream
	in := bufio.NewScanner(os.Stdin)
	fmt.Println("Enter Some text and end with new-line:")
	in.Scan()
	fmt.Printf("Here is what you entered : %s \n", in.Bytes())
}
