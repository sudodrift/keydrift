// Command mkfakehome writes the fake home folder used in the README demo.
//
//	go run ./internal/fakehome/mkfakehome DIR [--litellm]
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sudodrift/keydrift/internal/fakehome"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mkfakehome DIR [--litellm]")
		os.Exit(2)
	}
	dir, _ := filepath.Abs(os.Args[1])
	litellm := len(os.Args) > 2 && os.Args[2] == "--litellm"
	if err := fakehome.Write(dir, litellm); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
