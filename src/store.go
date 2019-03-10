package main

import (
	"fmt"
	"log"
	"os"
)

type store struct {
	items map[string]int
}

func (s *store) init() {
	s.items = make(map[string]int)
}

func (s *store) add(key string, value int) bool {
	s.items[key] = value
	return true
}

func (s *store) save(outFile string) bool {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
		return false
	}
	defer f.Close()

	for k, v := range s.items {
		data := fmt.Sprintf("%s %d\n", k, v)
		if _, err := f.Write([]byte(data)); err != nil {
			log.Fatal(err)
			return false
		}
	}
	return true
}
