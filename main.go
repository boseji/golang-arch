package main

import (
	"bufio"
	"fmt"
	"os"
)

// ---------------------------------------------------------
// EXERCISE: Unique Words
//
//  Create a program that prints the total and unique words
//  from an input stream.
//
//  1. Feed the swami_chinmayananda_geeta.txt to your program.
//
//  2. Scan the input using a new Scanner.
//
//  3. Configure the scanner to scan for the words.
//
//  4. Count the unique words using a map.
//
//  5. Print the total and unique words.
//
//
// EXPECTED OUTPUT
//
//  There are 104 words, 74 of them are unique.
//
// ---------------------------------------------------------

func main() {
	totalWords := 0
	wordcount := map[string]bool{}
	// Create a Input Stream
	in := bufio.NewScanner(os.Stdin)
	// Word Splitter
	in.Split(bufio.ScanWords)

	for in.Scan() {
		totalWords++
		word := in.Text()
		wordcount[word] = true
	}

	fmt.Printf("There are %d words, %d of them are unique.\n", totalWords, len(wordcount))
}
