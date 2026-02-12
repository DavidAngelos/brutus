// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Mock Hikvision IP camera login page for integration testing.
// Default credentials: admin/12345
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	defaultUser = "admin"
	defaultPass = "12345"
)

var loginPage = `<!DOCTYPE html>
<html>
<head>
    <title>HIKVISION - Network Camera</title>
    <meta charset="utf-8">
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: rgba(255,255,255,0.95);
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            width: 350px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #c62828;
            margin: 0;
            font-size: 24px;
            font-weight: bold;
            letter-spacing: 2px;
        }
        .logo p {
            color: #666;
            font-size: 12px;
            margin-top: 5px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            color: #333;
            margin-bottom: 8px;
            font-size: 14px;
        }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            border-color: #c62828;
            outline: none;
        }
        .login-btn {
            width: 100%;
            padding: 14px;
            background: #c62828;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .login-btn:hover {
            background: #a21d1d;
        }
        .error-msg {
            background: #ffebee;
            color: #c62828;
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 14px;
        }
        .device-info {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #999;
            font-size: 11px;
        }
        .camera-icon {
            font-size: 48px;
            color: #c62828;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <div class="camera-icon">&#128249;</div>
            <h1>HIKVISION</h1>
            <p>Network Camera</p>
        </div>
        {{ERROR}}
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">User Name</label>
                <input type="text" id="username" name="username" placeholder="admin" autocomplete="off">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Password">
            </div>
            <button type="submit" class="login-btn" id="submit-btn">Login</button>
        </form>
        <div class="device-info">
            <p>DS-2CD2143G2-I | Firmware: V5.7.1</p>
            <p>IP: 192.168.1.64</p>
        </div>
    </div>
</body>
</html>`

var dashboardPage = `<!DOCTYPE html>
<html>
<head>
    <title>HIKVISION - Live View</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #1a1a2e; color: white; }
        .header { background: #c62828; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; font-size: 18px; }
        .nav { background: #16213e; padding: 10px 20px; }
        .nav a { color: #aaa; text-decoration: none; margin-right: 25px; font-size: 14px; }
        .nav a:hover, .nav a.active { color: white; }
        .content { padding: 20px; }
        .video-container { background: #000; height: 400px; display: flex; justify-content: center; align-items: center; border-radius: 8px; }
        .video-container p { color: #666; }
        .logout { color: white; text-decoration: none; font-size: 14px; }
        .status { display: flex; gap: 30px; margin-top: 20px; }
        .status-card { background: #16213e; padding: 15px 25px; border-radius: 8px; }
        .status-card h3 { margin: 0 0 5px 0; color: #888; font-size: 12px; }
        .status-card p { margin: 0; font-size: 18px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>HIKVISION DS-2CD2143G2-I</h1>
        <a href="/logout" class="logout">Sign Out</a>
    </div>
    <div class="nav">
        <a href="#" class="active">Live View</a>
        <a href="#">Playback</a>
        <a href="#">Configuration</a>
        <a href="#">Maintenance</a>
    </div>
    <div class="content">
        <div class="video-container">
            <p>Live Video Stream - Channel 1</p>
        </div>
        <div class="status">
            <div class="status-card">
                <h3>Recording Status</h3>
                <p style="color: #4caf50;">Recording</p>
            </div>
            <div class="status-card">
                <h3>Resolution</h3>
                <p>2688x1520</p>
            </div>
            <div class="status-card">
                <h3>Bitrate</h3>
                <p>4096 Kbps</p>
            </div>
            <div class="status-card">
                <h3>Storage</h3>
                <p>78% Used</p>
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

	log.Printf("Hikvision Camera mock starting on port %s (creds: %s/%s)", port, defaultUser, defaultPass)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "DNVRS-Webs")
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
	errorMsg := `<div class="error-msg">Incorrect user name or password.</div>`
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
