package main

import (
	"fmt"
	"os"

	"github.com/andrewheberle/http-server/internal/pkg/cmd"
)

func main() {
	// run main command
	if err := cmd.Execute(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error during execution: %s\n", err)
		os.Exit(1)
	}
}
