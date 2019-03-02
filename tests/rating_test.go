package main

import (
	"fmt"
	"testing"
)

func TestRateConnection(t *testing.T) {
	pingNumber := 10
	rating, err := rateConnection(pingNumber)
	if err != nil {
		t.Errorf("%s\n", err)
	}
	fmt.Println(rating, pingNumber)
	if rating <= pingNumber {
		t.Errorf("Rating is should be less or equal to %d. Got %d\n", pingNumber, rating)
	}
}
func TestRateConnections(t *testing.T) {
	devices := map[string]int{
		"bc:8c:cd:f8:d2:f3": 2,
		"80:4e:81:52:1d:0d": 12,
		"b4:cb:57:69:c6:8":  1,
	}
	rated, err := rateConnections("en0", devices)
	if err != nil {
		t.Error(err)
	}
	t.Log(rated)
}
