package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ---------------------------------------------------------
// EXERCISE: Grep Clone
//
//  Create a grep clone. grep is a command-line utility for
//  searching plain-text data for lines that match a specific
//  pattern.
//
//  1. Feed the swami_chinmayananda_geeta to your program.
//
//  2. Accept a command-line argument for the pattern
//
//  3. Only print the lines that contains that pattern
//
//  4. If no pattern is provided, print all the lines
//
//
// EXPECTED OUTPUT
//
//  go run main.go geeta < swami_chinmayananda_geeta
//
//    Holy Geeta by Swami Chinmayananda
//    General introduction To Bhagawad Geeta
//    world and God, the Geeta is a hand-book of instructions as to how every human
//    Srimad Bhagawad Geeta, the Divine Song of the Lord, occurs in the Bhishma Parva
//
// ---------------------------------------------------------

func main() {
	// Regex for Cleaning the Non Unique characters
	rgx := regexp.MustCompile("[^a-z]+")
	// Take Arguments
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Enter the text query to be searched")
		return
	}
	query := rgx.ReplaceAllString(strings.ToLower(args[0]), "")
	// Create a Input Stream
	in := bufio.NewScanner(os.Stdin)

	for in.Scan() {
		line := in.Text()

		if strings.Contains(
			rgx.ReplaceAllString(strings.ToLower(line), ""),
			query,
		) {
			fmt.Println(line)
		}
	}
}
