// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Mock TP-Link router login page for integration testing.
// Default credentials: admin/admin
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	defaultUser = "admin"
	defaultPass = "admin"
)

var loginPage = `<!DOCTYPE html>
<html>
<head>
    <title>TP-LINK</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .logo { text-align: center; margin-bottom: 20px; }
        .logo h1 { color: #4aa564; margin: 0; font-size: 28px; }
        .logo p { color: #666; font-size: 12px; }
        h2 { color: #333; text-align: center; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #666; font-size: 14px; }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px;
            box-sizing: border-box; font-size: 14px;
        }
        button {
            width: 100%; padding: 12px; background: #4aa564; color: white;
            border: none; border-radius: 4px; cursor: pointer; font-size: 16px;
        }
        button:hover { background: #3d8a52; }
        .error { color: #d9534f; text-align: center; margin-bottom: 15px; padding: 10px; background: #fdf2f2; border-radius: 4px; }
        .model { text-align: center; color: #999; font-size: 11px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>TP-LINK</h1>
            <p>Wireless Router</p>
        </div>
        <h2>Login</h2>
        {{ERROR}}
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" required>
            </div>
            <button type="submit" id="login-btn">Login</button>
        </form>
        <p class="model">TL-WR841N v14 | Firmware: 3.16.9</p>
    </div>
</body>
</html>`

var dashboardPage = `<!DOCTYPE html>
<html>
<head>
    <title>TP-LINK - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; }
        .header { background: #4aa564; color: white; padding: 15px 20px; }
        .header h1 { margin: 0; font-size: 20px; }
        .nav { background: #333; padding: 10px 20px; }
        .nav a { color: white; text-decoration: none; margin-right: 20px; }
        .content { padding: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .logout { float: right; color: white; text-decoration: none; }
    </style>
</head>
<body>
    <div class="header">
        <h1>TP-LINK TL-WR841N</h1>
        <a href="/logout" class="logout">Logout</a>
    </div>
    <div class="nav">
        <a href="#">Status</a>
        <a href="#">Network</a>
        <a href="#">Wireless</a>
        <a href="#">Security</a>
        <a href="#">Settings</a>
    </div>
    <div class="content">
        <div class="card">
            <h2>Welcome, Administrator</h2>
            <p>System Status: Online</p>
            <p>Connected Devices: 5</p>
            <p>Uptime: 3 days, 14 hours</p>
        </div>
        <div class="card">
            <h3>Quick Actions</h3>
            <p>Firmware Version: 3.16.9 (Up to date)</p>
            <p>WAN IP: 203.0.113.42</p>
            <p>LAN IP: 192.168.0.1</p>
        </div>
    </div>
</body>
</html>`

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", handleLogin)
	http.HandleFunc("/login", handleLoginPost)
	http.HandleFunc("/dashboard", handleDashboard)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/health", handleHealth)

	log.Printf("TP-Link Router mock starting on port %s (creds: %s/%s)", port, defaultUser, defaultPass)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "TP-LINK Router")
	fmt.Fprint(w, replacePlaceholder(loginPage, ""))
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if username == defaultUser && password == defaultPass {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	errorMsg := `<div class="error">Invalid username or password</div>`
	fmt.Fprint(w, replacePlaceholder(loginPage, errorMsg))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, dashboardPage)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

func replacePlaceholder(page, errorMsg string) string {
	if errorMsg == "" {
		return replaceString(page, "{{ERROR}}", "")
	}
	return replaceString(page, "{{ERROR}}", errorMsg)
}

func replaceString(s, old, new string) string {
	result := ""
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result += new
			i += len(old)
		} else {
			result += string(s[i])
			i++
		}
	}
	return result
}
