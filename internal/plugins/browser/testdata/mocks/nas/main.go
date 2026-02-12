// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Mock Synology NAS login page for integration testing.
// Default credentials: admin/synology
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	defaultUser = "admin"
	defaultPass = "synology"
)

var loginPage = `<!DOCTYPE html>
<html>
<head>
    <title>Synology DiskStation</title>
    <meta charset="utf-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-wrapper {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 420px;
            overflow: hidden;
        }
        .login-header {
            background: #4a5568;
            padding: 30px;
            text-align: center;
        }
        .logo {
            font-size: 32px;
            color: white;
            font-weight: 300;
        }
        .logo span { font-weight: 600; }
        .model-name {
            color: #a0aec0;
            font-size: 14px;
            margin-top: 8px;
        }
        .login-form {
            padding: 40px;
        }
        .form-group {
            margin-bottom: 24px;
        }
        .form-group label {
            display: block;
            color: #4a5568;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
        }
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        .form-group input:focus {
            border-color: #667eea;
            outline: none;
        }
        .login-btn {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        .error-message {
            background: #fed7d7;
            color: #c53030;
            padding: 14px;
            border-radius: 8px;
            margin-bottom: 24px;
            font-size: 14px;
            text-align: center;
        }
        .login-footer {
            text-align: center;
            padding: 20px;
            background: #f7fafc;
            border-top: 1px solid #e2e8f0;
        }
        .login-footer p {
            color: #718096;
            font-size: 12px;
        }
        .checkbox-group {
            display: flex;
            align-items: center;
            margin-bottom: 24px;
        }
        .checkbox-group input {
            width: auto;
            margin-right: 8px;
        }
        .checkbox-group label {
            margin: 0;
            font-size: 14px;
            color: #718096;
        }
    </style>
</head>
<body>
    <div class="login-wrapper">
        <div class="login-header">
            <div class="logo">Synology <span>DiskStation</span></div>
            <div class="model-name">DS920+</div>
        </div>
        <div class="login-form">
            {{ERROR}}
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">Account</label>
                    <input type="text" id="username" name="username" placeholder="Username" autocomplete="username">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Password" autocomplete="current-password">
                </div>
                <div class="checkbox-group">
                    <input type="checkbox" id="remember" name="remember">
                    <label for="remember">Remember me</label>
                </div>
                <button type="submit" class="login-btn" id="login-submit">Sign In</button>
            </form>
        </div>
        <div class="login-footer">
            <p>DSM 7.2-64570 Update 3</p>
            <p>&copy; 2024 Synology Inc.</p>
        </div>
    </div>
</body>
</html>`

var dashboardPage = `<!DOCTYPE html>
<html>
<head>
    <title>Synology DiskStation - Main Menu</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #2d3748; }
        .desktop {
            min-height: 100vh;
            padding: 20px;
            background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%);
        }
        .taskbar {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 48px;
            background: rgba(0,0,0,0.8);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            z-index: 1000;
        }
        .taskbar-left { display: flex; align-items: center; gap: 20px; }
        .logo { color: white; font-size: 16px; font-weight: 600; }
        .taskbar-right { display: flex; align-items: center; gap: 15px; }
        .taskbar-right a { color: #a0aec0; text-decoration: none; font-size: 14px; }
        .taskbar-right a:hover { color: white; }
        .app-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
            gap: 20px;
            padding: 80px 40px;
            max-width: 800px;
        }
        .app-icon {
            text-align: center;
            padding: 20px 10px;
            border-radius: 12px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .app-icon:hover { background: rgba(255,255,255,0.1); }
        .app-icon .icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            margin: 0 auto 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        .app-icon .name { color: white; font-size: 12px; }
        .widget {
            position: fixed;
            right: 40px;
            top: 80px;
            width: 320px;
            background: rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 20px;
            backdrop-filter: blur(10px);
        }
        .widget h3 { color: white; font-size: 14px; margin-bottom: 15px; }
        .widget-stat {
            display: flex;
            justify-content: space-between;
            color: #a0aec0;
            font-size: 13px;
            margin-bottom: 10px;
        }
        .widget-stat value { color: white; }
        .storage-bar {
            height: 8px;
            background: rgba(255,255,255,0.2);
            border-radius: 4px;
            overflow: hidden;
            margin: 15px 0;
        }
        .storage-used { height: 100%; background: #667eea; width: 42%; }
    </style>
</head>
<body>
    <div class="taskbar">
        <div class="taskbar-left">
            <span class="logo">Synology DiskStation</span>
        </div>
        <div class="taskbar-right">
            <a href="#">admin</a>
            <a href="/logout">Sign Out</a>
        </div>
    </div>
    <div class="desktop">
        <div class="app-grid">
            <div class="app-icon">
                <div class="icon">&#128193;</div>
                <div class="name">File Station</div>
            </div>
            <div class="app-icon">
                <div class="icon">&#9881;</div>
                <div class="name">Control Panel</div>
            </div>
            <div class="app-icon">
                <div class="icon">&#128230;</div>
                <div class="name">Package Center</div>
            </div>
            <div class="app-icon">
                <div class="icon">&#128202;</div>
                <div class="name">Resource Monitor</div>
            </div>
            <div class="app-icon">
                <div class="icon">&#128247;</div>
                <div class="name">Surveillance</div>
            </div>
            <div class="app-icon">
                <div class="icon">&#127909;</div>
                <div class="name">Video Station</div>
            </div>
        </div>
        <div class="widget">
            <h3>System Health</h3>
            <div class="widget-stat">
                <span>CPU</span>
                <value>12%</value>
            </div>
            <div class="widget-stat">
                <span>Memory</span>
                <value>3.2 GB / 8 GB</value>
            </div>
            <h3 style="margin-top: 20px;">Storage</h3>
            <div class="storage-bar"><div class="storage-used"></div></div>
            <div class="widget-stat">
                <span>Volume 1</span>
                <value>8.4 TB / 20 TB</value>
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
	http.HandleFunc("/webman/index.cgi", handleDashboard)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/health", handleHealth)

	log.Printf("Synology NAS mock starting on port %s (creds: %s/%s)", port, defaultUser, defaultPass)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "nginx")
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
	errorMsg := `<div class="error-message">Incorrect login credentials. Please try again.</div>`
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
