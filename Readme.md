# Glassworm (Sentinel)

A lightweight GraphQL security scanner written in C. Glassworm (binary name: `sentinel`) can analyze GraphQL introspection schemas, detect GraphQL endpoints from a list of URLs, and highlight potentially sensitive fields — all from a single command-line tool.

## ✨ Features

- **Schema analysis** – Parses GraphQL introspection JSON and prints a readable schema representation (types, fields, directives, etc.).
- **Security analysis** – Flags fields containing sensitive keywords (`password`, `token`, `secret`, `apiKey`, `credit`, `ssn`, etc.) and reports them.
- **GraphQL endpoint detection** – Reads a file containing URLs, sends a lightweight probe (`uni.json`), and records endpoints that respond with GraphQL-like content (`__schema`, `data`, `errors`, `query`).
- **Gobuster integration** – Can consume output from Gobuster to discover GraphQL paths.
- **Unix socket support** – Provides primitives for inter-process communication via a Unix domain socket (`/tmp/sentinel.sock`).
- **Sanitizer build** – `make sanitize` builds with AddressSanitizer and UndefinedBehaviorSanitizer for development.

## 📦 Dependencies

| Library | Purpose |
|---------|---------|
| `libcurl` | HTTP/HTTPS requests |
| `cJSON`   | JSON parsing |
| `pthread` | Threading (linked but not heavily used in current code) |

Install on Debian/Ubuntu:

```bash
sudo apt install libcurl4-openssl-dev libcjson-dev build-essential