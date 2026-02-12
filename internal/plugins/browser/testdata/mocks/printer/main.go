// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Mock HP printer login page for integration testing.
// Default credentials: admin/(empty password)
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	defaultUser = "admin"
	defaultPass = "" // HP printers often have empty default password
)

var loginPage = `<!DOCTYPE html>
<html>
<head>
    <title>HP LaserJet - Sign In</title>
    <meta charset="utf-8">
    <style>
        body {
            font-family: 'HP Simplified', Arial, sans-serif;
            background: #f4f4f4;
            margin: 0;
            padding: 0;
        }
        .header {
            background: #0096d6;
            padding: 15px 30px;
            color: white;
        }
        .header h1 {
            margin: 0;
            font-size: 20px;
            font-weight: normal;
        }
        .container {
            max-width: 500px;
            margin: 60px auto;
            padding: 0 20px;
        }
        .login-box {
            background: white;
            padding: 40px;
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .login-box h2 {
            margin: 0 0 30px 0;
            color: #333;
            font-weight: normal;
            font-size: 24px;
        }
        .form-field {
            margin-bottom: 25px;
        }
        .form-field label {
            display: block;
            color: #666;
            margin-bottom: 8px;
            font-size: 14px;
        }
        .form-field input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        .form-field input:focus {
            border-color: #0096d6;
            outline: none;
        }
        .submit-btn {
            background: #0096d6;
            color: white;
            border: none;
            padding: 14px 30px;
            font-size: 16px;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
        }
        .submit-btn:hover {
            background: #007ab3;
        }
        .error-box {
            background: #fff3f3;
            border: 1px solid #ffcccc;
            color: #cc0000;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 25px;
            font-size: 14px;
        }
        .help-text {
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 12px;
        }
        .footer {
            text-align: center;
            padding: 30px;
            color: #999;
            font-size: 11px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>HP LaserJet Pro MFP M428fdw</h1>
    </div>
    <div class="container">
        <div class="login-box">
            <h2>Sign In</h2>
            {{ERROR}}
            <form method="POST" action="/login">
                <div class="form-field">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" value="admin">
                </div>
                <div class="form-field">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter password">
                </div>
                <button type="submit" class="submit-btn" id="signInButton">Sign In</button>
            </form>
            <div class="help-text">
                <p>Default administrator username is "admin".</p>
                <p>If you have not set a password, leave the password field blank.</p>
            </div>
        </div>
    </div>
    <div class="footer">
        <p>HP LaserJet Pro MFP M428fdw | Firmware: 2409A</p>
        <p>&copy; Copyright 2024 HP Development Company, L.P.</p>
    </div>
</body>
</html>`

var dashboardPage = `<!DOCTYPE html>
<html>
<head>
    <title>HP LaserJet - Information</title>
    <style>
        body { font-family: 'HP Simplified', Arial, sans-serif; background: #f4f4f4; margin: 0; }
        .header { background: #0096d6; padding: 15px 30px; color: white; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 20px; font-weight: normal; }
        .nav { background: #333; padding: 0; }
        .nav a { color: white; text-decoration: none; padding: 15px 20px; display: inline-block; font-size: 14px; }
        .nav a:hover, .nav a.active { background: #0096d6; }
        .content { padding: 30px; max-width: 1200px; margin: 0 auto; }
        .card { background: white; padding: 25px; border-radius: 4px; margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }
        .card h2 { margin: 0 0 20px 0; color: #333; font-size: 18px; font-weight: normal; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .status-item { padding: 15px; background: #f9f9f9; border-radius: 4px; }
        .status-item label { display: block; color: #666; font-size: 12px; margin-bottom: 5px; }
        .status-item value { font-size: 16px; color: #333; }
        .logout { color: white; text-decoration: none; font-size: 14px; }
        .supplies { margin-top: 15px; }
        .supply-bar { height: 20px; background: #e0e0e0; border-radius: 10px; overflow: hidden; margin: 5px 0; }
        .supply-level { height: 100%; background: #0096d6; }
        .supply-level.low { background: #ff9800; }
        .supply-level.critical { background: #f44336; }
    </style>
</head>
<body>
    <div class="header">
        <h1>HP LaserJet Pro MFP M428fdw</h1>
        <a href="/logout" class="logout">Sign Out</a>
    </div>
    <div class="nav">
        <a href="#" class="active">Information</a>
        <a href="#">General</a>
        <a href="#">Copy/Print</a>
        <a href="#">Scan</a>
        <a href="#">Fax</a>
        <a href="#">Troubleshooting</a>
        <a href="#">Security</a>
        <a href="#">HP Web Services</a>
    </div>
    <div class="content">
        <div class="card">
            <h2>Device Status</h2>
            <div class="status-grid">
                <div class="status-item">
                    <label>Status</label>
                    <value style="color: #4caf50;">Ready</value>
                </div>
                <div class="status-item">
                    <label>IP Address</label>
                    <value>192.168.1.100</value>
                </div>
                <div class="status-item">
                    <label>Serial Number</label>
                    <value>PHBCJ2R8K1</value>
                </div>
                <div class="status-item">
                    <label>Firmware</label>
                    <value>2409A</value>
                </div>
            </div>
        </div>
        <div class="card">
            <h2>Supplies Status</h2>
            <div class="supplies">
                <p>Black Cartridge (HP 58A)</p>
                <div class="supply-bar"><div class="supply-level" style="width: 65%;"></div></div>
                <p>Imaging Drum</p>
                <div class="supply-bar"><div class="supply-level" style="width: 85%;"></div></div>
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

	log.Printf("HP Printer mock starting on port %s (creds: %s/(empty))", port, defaultUser)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "HP HTTP Server")
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
	errorMsg := `<div class="error-box">The password you entered is incorrect. Please try again.</div>`
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
