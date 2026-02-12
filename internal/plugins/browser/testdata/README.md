# Browser Plugin Test Infrastructure

This directory contains mock embedded device login pages for testing the browser plugin.

## Mock Devices

| Device | Port | Default Credentials | Description |
|--------|------|---------------------|-------------|
| TP-Link Router | 8081 | `admin` / `admin` | Simulates TL-WR841N wireless router |
| Hikvision Camera | 8082 | `admin` / `12345` | Simulates DS-2CD2143G2-I IP camera |
| HP Printer | 8083 | `admin` / *(empty)* | Simulates LaserJet Pro MFP M428fdw |
| Synology NAS | 8084 | `admin` / `synology` | Simulates DS920+ DiskStation |
| Generic Panel | 8085 | `admin` / `password` | Generic admin panel |

## Quick Start

```bash
# Start all mock services
cd internal/plugins/browser/testdata
docker-compose up -d

# Verify services are running
curl http://localhost:8081/health  # Router
curl http://localhost:8082/health  # Camera
curl http://localhost:8083/health  # Printer
curl http://localhost:8084/health  # NAS
curl http://localhost:8085/health  # Generic

# Run E2E tests
cd ../../..
go test -tags=e2e ./internal/plugins/browser/... -v

# Stop services when done
cd testdata
docker-compose down
```

## Running Individual Mock Servers

For development, you can run individual mocks without Docker:

```bash
# Run router mock directly
cd mocks/router
go run main.go

# Access at http://localhost:8080
```

## Test Structure

### Unit Tests (`*_test.go`)
- Run without external dependencies
- Use `testing.Short()` to skip slow tests
- Mock HTTP responses where needed

### Integration Tests (`integration_test.go`)
- Require Chrome/Chromium
- Use httptest.Server for simple HTTP mocks
- Run with: `go test ./internal/plugins/browser/... -v`

### E2E Tests (`e2e_test.go`)
- Require Docker AND Chrome
- Use realistic mock device login pages
- Run with: `go test -tags=e2e ./internal/plugins/browser/... -v`

## Mock Device Details

### TP-Link Router (8081)
- **Server Header**: `TP-LINK Router`
- **Login Form**: POST `/login` with `username` + `password`
- **Success Redirect**: `/dashboard`
- **Error Display**: Red box with "Invalid username or password"

### Hikvision Camera (8082)
- **Server Header**: `DNVRS-Webs`
- **Login Form**: POST `/login` with `username` + `password`
- **Success Redirect**: `/dashboard`
- **Error Display**: Red banner with "Incorrect user name or password"

### HP Printer (8083)
- **Server Header**: `HP HTTP Server`
- **Login Form**: POST `/login` with `username` + `password`
- **Success Redirect**: `/dashboard`
- **Error Display**: Box with "The password you entered is incorrect"
- **Note**: Empty password is the default (typical for HP printers)

### Synology NAS (8084)
- **Server Header**: `nginx`
- **Login Form**: POST `/login` with `username` + `password`
- **Success Redirect**: `/dashboard`
- **Error Display**: Box with "Incorrect login credentials"

### Generic Admin Panel (8085)
- **Server Header**: (none)
- **Login Form**: POST `/login` with `username` + `password`
- **Success Redirect**: `/dashboard`
- **Error Display**: Alert with "Invalid credentials"

## Architecture

```
testdata/
├── docker-compose.yml       # Orchestrates all mock services
├── README.md                # This file
└── mocks/
    ├── Dockerfile           # Multi-stage build for all mocks
    ├── router/main.go       # TP-Link router mock
    ├── camera/main.go       # Hikvision camera mock
    ├── printer/main.go      # HP printer mock
    ├── nas/main.go          # Synology NAS mock
    └── generic/main.go      # Generic admin panel mock
```

## Testing Workflow

1. **Form Detection**: Tests that the browser plugin correctly identifies username/password fields
2. **Form Filling**: Tests that credentials are properly entered into form fields
3. **Login Submission**: Tests that the form is submitted correctly
4. **Success Detection**: Tests that successful logins are identified (URL change, form disappears)
5. **Error Detection**: Tests that failed logins are identified (error messages appear)

## Adding New Mock Devices

1. Create a new directory: `mocks/newdevice/`
2. Add `main.go` implementing the login page
3. Update `docker-compose.yml` to include the new service
4. Add test case to `e2e_test.go`

Template for new mock:
```go
package main

import (
    "net/http"
    "os"
)

const (
    defaultUser = "admin"
    defaultPass = "admin"
)

var loginPage = `<!DOCTYPE html>...`

func main() {
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    http.HandleFunc("/", handleLogin)
    http.HandleFunc("/login", handleLoginPost)
    http.HandleFunc("/dashboard", handleDashboard)
    http.HandleFunc("/health", handleHealth)

    http.ListenAndServe(":"+port, nil)
}
```
