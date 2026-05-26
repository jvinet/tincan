package main

import (
	"os"

	"github.com/jvinet/tincan/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
