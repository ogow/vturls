// main.go
// Command-line interface to use vtclient. Place this in package main.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	vtclient "github.com/ogow/vturls/pkg"
)

// countdown prints a dynamic countdown to stdout.
// func countdown(seconds int) {
// 	for i := seconds; i > 0; i-- {
// 		log.Printf("Waiting %2d seconds...\r", i)
// 		time.Sleep(time.Second)
// 	}
// 	fmt.Print("\r")
// }

// cleanDomain strips http(s):// prefix.
func cleanDomain(input string) string {
	input = strings.TrimSpace(input)
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")
	return input
}

func main() {
	// Single flag -t with comma-separated tokens
	tokens := flag.String("t", "", "Comma-separated VirusTotal API tokens")
	flag.Parse()

	if *tokens == "" {
		log.Println("Error: -t flag must contain at least one API token")
		os.Exit(1)
	}
	apiKeys := strings.Split(*tokens, ",")

	// Read domains from stdin if no arg provided, else from file or direct arg
	domains := []string{}
	args := flag.Args()
	if len(args) == 0 {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			d := cleanDomain(s.Text())
			if d != "" {
				domains = append(domains, d)
			}
		}
	} else {
		in := args[0]
		if info, err := os.Stat(in); err == nil && !info.IsDir() {
			f, err := os.Open(in)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
			defer f.Close()
			s := bufio.NewScanner(f)
			for s.Scan() {
				d := cleanDomain(s.Text())
				if d != "" {
					domains = append(domains, d)
				}
			}
		} else {
			domains = append(domains, cleanDomain(in))
		}
	}

	client, err := vtclient.NewClient(apiKeys)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	requestCount := 0
	for _, domain := range domains {
		log.Printf("[!] Fetching data for domain: %s (using API key #%d)\n", domain, client.CurrentKeyIndex())
		urls, err := client.FetchUndetectedURLs(domain)
		if err != nil {
			if err.Error() == "all API keys failed after 1 minute" {
				log.Println("Error: none of the API keys succeeded after 1 minute, exiting.")
				os.Exit(1)
			}
			log.Printf("Error fetching %s: %v\n", domain, err)
		} else if len(urls) == 0 {
			log.Printf("No undetected URLs for domain: %s\n", domain)
		} else {
			log.Printf("Undetected URLs for domain %s:\n", domain)
			for _, u := range urls {
				fmt.Println(u)
			}
		}

		// countdown(20)

		requestCount++
		if requestCount >= 5 {
			requestCount = 0
			client.RotateKey()
			fmt.Printf("Rotated API key to #%d\n", client.CurrentKeyIndex())
		}
	}
}
