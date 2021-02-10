package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ---------------------------------------------------------
// EXERCISE: Unique Words 2
//
//  Use your solution from the previous "Unique Words"
//  exercise.
//
//  Before adding the words to your map, remove the
//  punctuation characters and numbers from them.
//
//
// BE CAREFUL
//
//  Now the swami_chinmayananda_geeta.txt contains upper and lower
//  case letters too.
//
//
// EXPECTED OUTPUT
//
//  go run main.go < swami_chinmayananda_geeta.txt
//
//   There are 104 words, 70 of them are unique.
//
// ---------------------------------------------------------
func main() {
	totalWords := 0
	wordcount := map[string]bool{}
	// Regex for Cleaning the Non Unique characters
	rgx := regexp.MustCompile("[^a-z]+")
	// Create a Input Stream
	in := bufio.NewScanner(os.Stdin)
	// Word Splitter
	in.Split(bufio.ScanWords)

	for in.Scan() {
		totalWords++
		word := strings.ToLower(in.Text())
		word = rgx.ReplaceAllString(word, "")
		wordcount[word] = true
	}

	fmt.Printf("There are %d words, %d of them are unique.\n", totalWords, len(wordcount))
}
