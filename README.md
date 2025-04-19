# vturls CLI

Vtclient is a Go-based command-line tool and library for fetching undetected URLs for a domain from the VirusTotal v2 API.

## Features
Handles automatic API key rotation on quota errors.

Fetches and prints undetected URLs per domain.

Supports reading domains from stdin, a file, or as a direct argument.

Built-in rate limiting with countdown between requests.

## Installation
```bash
git clone https://github.com/yourusername/vtclient.git
cd vtclient
go build -o vtclient main.go
```

## Usage
```bash
./vtclient -t <api_key1>,<api_key2>,... [domain|filename]
```

+ `-t` — Required: Comma-separated VirusTotal API keys.
+ `[domain|filename]` — Optional:
    + A domain name (e.g., example.com)
    + A filename containing a list of domains (one per line)
    + If omitted, domains are read from stdin.

### Examples
**Single domain:**
```bash
./vtclient -t abc123,def456 example.com
```

**List from file:**

```bash
./vtclient -t abc123 domains.txt
```

**Piped input:**

```bash
cat domains.txt | ./vtclient -t abc123
```

## Notes

+ After 5 requests, the client rotates to the next API key.
+ The tool waits 20 seconds between domain queries to respect VirusTotal's rate limits.
+ If all API keys are exhausted for 1 minute, the tool exits with an error.

API Reference
Uses VirusTotal v2 API:

```plain
https://www.virustotal.com/vtapi/v2/domain/report?apikey=<apikey>&domain=<domain>
```

## License
MIT License


