package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("distributed-scanner CLI")
	if len(os.Args) < 2 {
		fmt.Println("Usage: scanner-cli <command>")
		fmt.Println("Commands: scan, status, results, report")
		os.Exit(1)
	}
	// CLI implementation will be added in later phases
	fmt.Printf("command: %s (not yet implemented)\n", os.Args[1])
}
