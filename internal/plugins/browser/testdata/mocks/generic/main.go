// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Mock generic admin panel for integration testing.
// Default credentials: admin/password
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	defaultUser = "admin"
	defaultPass = "password"
)

var loginPage = `<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Login</title>
    <meta charset="utf-8">
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #f0f2f5;
            margin: 0;
            padding: 40px 20px;
        }
        .login-container {
            max-width: 400px;
            margin: 0 auto;
        }
        .login-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            padding: 32px;
        }
        h1 {
            text-align: center;
            color: #1a1a1a;
            font-size: 24px;
            margin: 0 0 8px 0;
        }
        .subtitle {
            text-align: center;
            color: #666;
            font-size: 14px;
            margin-bottom: 32px;
        }
        .input-group {
            margin-bottom: 20px;
        }
        .input-group label {
            display: block;
            color: #333;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 6px;
        }
        .input-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 15px;
            box-sizing: border-box;
        }
        .input-group input:focus {
            outline: none;
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37,99,235,0.1);
        }
        .btn-login {
            width: 100%;
            padding: 12px;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 500;
            cursor: pointer;
        }
        .btn-login:hover {
            background: #1d4ed8;
        }
        .alert-error {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .footer {
            text-align: center;
            margin-top: 24px;
            color: #9ca3af;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <h1>Admin Panel</h1>
            <p class="subtitle">Sign in to your account</p>
            {{ERROR}}
            <form method="POST" action="/login">
                <div class="input-group">
                    <label for="user">Username</label>
                    <input type="text" id="user" name="username" placeholder="Enter username" required>
                </div>
                <div class="input-group">
                    <label for="pass">Password</label>
                    <input type="password" id="pass" name="password" placeholder="Enter password" required>
                </div>
                <button type="submit" class="btn-login" id="loginBtn">Sign In</button>
            </form>
        </div>
        <p class="footer">Generic Admin Panel v1.0</p>
    </div>
</body>
</html>`

var dashboardPage = `<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Dashboard</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 0; background: #f0f2f5; }
        .header { background: #1a1a1a; color: white; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 18px; font-weight: 500; }
        .header a { color: #9ca3af; text-decoration: none; font-size: 14px; }
        .header a:hover { color: white; }
        .main { padding: 24px; max-width: 1200px; margin: 0 auto; }
        .card { background: white; border-radius: 8px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card h2 { margin: 0 0 16px 0; font-size: 18px; color: #1a1a1a; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
        .stat { background: #f9fafb; padding: 16px; border-radius: 6px; }
        .stat-value { font-size: 24px; font-weight: 600; color: #1a1a1a; }
        .stat-label { font-size: 13px; color: #6b7280; margin-top: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Admin Dashboard</h1>
        <a href="/logout">Logout</a>
    </div>
    <div class="main">
        <div class="card">
            <h2>Welcome back, Administrator</h2>
            <p style="color: #6b7280;">You have successfully logged in to the admin panel.</p>
        </div>
        <div class="stats">
            <div class="stat">
                <div class="stat-value">1,234</div>
                <div class="stat-label">Total Users</div>
            </div>
            <div class="stat">
                <div class="stat-value">567</div>
                <div class="stat-label">Active Sessions</div>
            </div>
            <div class="stat">
                <div class="stat-value">89</div>
                <div class="stat-label">Pending Tasks</div>
            </div>
            <div class="stat">
                <div class="stat-value">99.9%</div>
                <div class="stat-label">Uptime</div>
            </div>
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

	log.Printf("Generic Admin Panel mock starting on port %s (creds: %s/%s)", port, defaultUser, defaultPass)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
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
	errorMsg := `<div class="alert-error">Invalid credentials. Please try again.</div>`
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
	result := ""
	old := "{{ERROR}}"
	for i := 0; i < len(page); {
		if i+len(old) <= len(page) && page[i:i+len(old)] == old {
			result += errorMsg
			i += len(old)
		} else {
			result += string(page[i])
			i++
		}
	}
	return result
}
