package main

import (
	"fmt"
	"testing"
)

func TestAcl(t *testing.T) {
	if err := Parse("./access.list"); err != nil {
		t.Error(err)
		return
	}

	r := GetReport("www.google.com", "137.255.1.2")
	fmt.Println(r)
	r = GetReport("", "162.197.25.32")
	fmt.Println(r)
	r = GetReport("www.google.com", "162.197.25.32")
	fmt.Println(r)
	r = GetReport("www.google.cm", "162.197.25.32")
	fmt.Println(r)
	r = GetReport("www.google.cdm", "162.197.25.32")
	fmt.Println(r)

	Test("www.google.com", "137.255.1.2")
	Test("www.google.com", "162.197.25.32")
}
