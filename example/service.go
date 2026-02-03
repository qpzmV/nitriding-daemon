package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

const nitridingURL = "http://127.0.0.1:8080/enclave/ready"

// signalReady notifies nitriding that the application is ready.
func signalReady() error {
	resp, err := http.Get(nitridingURL)
	if err != nil {
		return fmt.Errorf("failed to signal ready: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code %d but got %d", http.StatusOK, resp.StatusCode)
	}
	return nil
}

// fetchAddr fetches data from an external URL to demonstrate network access.
func fetchAddr() error {
	url := "https://raw.githubusercontent.com/brave/nitriding-daemon/master/README.md"
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	// Read up to 100 bytes
	buf := make([]byte, 100)
	n, err := io.ReadAtLeast(resp.Body, buf, 1)
	if err != nil && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("failed to read response: %w", err)
	}
	fmt.Printf("[go] Fetched %d bytes of README.md.\n", n)
	return nil
}

func main() {
	if err := signalReady(); err != nil {
		fmt.Printf("[go] Error signaling ready: %v\n", err)
		return
	}
	fmt.Println("[go] Signalled to nitriding that we're ready.")

	time.Sleep(1 * time.Second)

	if err := fetchAddr(); err != nil {
		fmt.Printf("[go] Error fetching URL: %v\n", err)
		return
	}
	fmt.Println("[go] Made Web request to the outside world.")
}
