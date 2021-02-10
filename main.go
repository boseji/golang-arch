package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ---------------------------------------------------------
// EXERCISE: Uppercaser
//
//  Use a scanner to convert the lines to uppercase, and
//  print them.
//
//  1. Feed the swami_chinmayananda_geeta.txt to your program.
//
//  2. Scan the input using a new Scanner.
//
//  3. Print each line.
//
// EXPECTED OUTPUT
//  Please run the solution to see the expected output.
// ---------------------------------------------------------

func main() {
	// Create a Input Stream
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		fmt.Printf("%s\n", strings.ToUpper(in.Text()))
	}
}
