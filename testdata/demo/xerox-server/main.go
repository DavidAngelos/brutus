// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

// Xerox WorkCentre Printer Mock Server
// Demonstrates Brutus AI Browser Plugin capability
// Default credentials: admin/1111 (common Xerox default)

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
)

const (
	validUser = "admin"
	validPass = "1111"
	port      = ":80"
)

var (
	sessions   = make(map[string]string)
	sessionsMu sync.RWMutex
)

const loginPage = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Xerox WorkCentre 7855</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: "Segoe UI", Arial, sans-serif; background: #f0f0f0; min-height: 100vh; }
        .header { background: linear-gradient(180deg, #c8102e 0%%, #a00d25 100%%); padding: 15px 30px; display: flex; align-items: center; justify-content: space-between; }
        .xerox-logo { display: flex; align-items: center; gap: 12px; }
        .xerox-text { color: white; font-size: 28px; font-weight: 700; letter-spacing: 2px; }
        .product-name { color: rgba(255,255,255,0.9); font-size: 14px; }
        .main-container { display: flex; justify-content: center; align-items: center; min-height: calc(100vh - 66px); padding: 40px; }
        .login-box { background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); width: 420px; overflow: hidden; }
        .login-header { background: #333; color: white; padding: 24px; text-align: center; }
        .login-header h2 { font-size: 18px; font-weight: 400; }
        .login-body { padding: 32px 28px; }
        .form-group { margin-bottom: 22px; }
        .form-group label { display: block; margin-bottom: 8px; color: #333; font-size: 14px; font-weight: 500; }
        .form-group input { width: 100%%; padding: 14px 16px; border: 2px solid #ddd; border-radius: 4px; font-size: 15px; transition: border-color 0.2s; }
        .form-group input:focus { border-color: #c8102e; outline: none; }
        .login-btn { width: 100%%; padding: 14px; background: #c8102e; color: white; border: none; border-radius: 4px; font-size: 16px; font-weight: 600; cursor: pointer; text-transform: uppercase; letter-spacing: 1px; }
        .login-btn:hover { background: #a00d25; }
        .error-message { background: #ffebee; color: #c62828; padding: 14px; border-radius: 4px; margin-bottom: 22px; font-size: 14px; display: %s; border-left: 4px solid #c62828; }
        .footer { text-align: center; padding: 20px; font-size: 11px; color: #999; border-top: 1px solid #eee; background: #fafafa; }
    </style>
</head>
<body>
    <div class="header">
        <div class="xerox-logo">
            <span class="xerox-text">XEROX</span>
        </div>
        <div class="product-name">WorkCentre 7855</div>
    </div>
    <div class="main-container">
        <div class="login-box">
            <div class="login-header">
                <h2>Device Administrator Login</h2>
            </div>
            <div class="login-body">
                <div class="error-message">Login failed. Invalid username or password.</div>
                <form method="POST" action="/properties/authentication/luidLogin.php">
                    <input type="hidden" name="_fun_function" value="HTTP_Authenticate_fn">
                    <input type="hidden" name="_tid_" value="XRX_SPAR7855">
                    <div class="form-group">
                        <label for="webUIuserName">User ID</label>
                        <input type="text" id="webUIuserName" name="webUIuserName" placeholder="Enter User ID" required autocomplete="off">
                    </div>
                    <div class="form-group">
                        <label for="webUIpasswd">Passcode</label>
                        <input type="password" id="webUIpasswd" name="webUIpasswd" placeholder="Enter Passcode" autocomplete="off">
                    </div>
                    <button type="submit" class="login-btn">Log In</button>
                </form>
            </div>
            <div class="footer">Xerox WorkCentre 7855 | System Software 073.040.075.09100</div>
        </div>
    </div>
</body>
</html>`

const dashboardPage = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Xerox WorkCentre 7855 - Device Status</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: "Segoe UI", Arial, sans-serif; background: #f0f0f0; }
        .header { background: linear-gradient(180deg, #c8102e 0%%, #a00d25 100%%); padding: 15px 30px; display: flex; align-items: center; justify-content: space-between; }
        .xerox-logo { display: flex; align-items: center; gap: 12px; }
        .xerox-text { color: white; font-size: 28px; font-weight: 700; letter-spacing: 2px; }
        .user-info { color: rgba(255,255,255,0.9); font-size: 13px; }
        .nav { background: #333; padding: 0 30px; }
        .nav a { color: #ccc; text-decoration: none; padding: 15px 20px; display: inline-block; font-size: 13px; }
        .nav a:hover { background: #444; color: white; }
        .nav a.active { background: #c8102e; color: white; }
        .content { padding: 30px; max-width: 1100px; margin: 0 auto; }
        .success-banner { background: #e8f5e9; border: 1px solid #a5d6a7; border-radius: 4px; padding: 18px 22px; margin-bottom: 24px; color: #2e7d32; border-left: 4px solid #4caf50; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; }
        .card { background: white; border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; }
        .card-header { padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 600; color: #333; font-size: 15px; background: #fafafa; }
        .card-body { padding: 20px; }
        .info-row { display: flex; padding: 12px 0; border-bottom: 1px solid #f0f0f0; }
        .info-row:last-child { border-bottom: none; }
        .info-label { width: 140px; color: #666; font-size: 13px; }
        .info-value { flex: 1; font-size: 13px; font-weight: 500; color: #333; }
        .supply-bar { height: 8px; background: #e0e0e0; border-radius: 4px; overflow: hidden; margin-top: 6px; }
        .supply-fill { height: 100%%; border-radius: 4px; }
        .supply-fill.cyan { background: #00bcd4; }
        .supply-fill.magenta { background: #e91e63; }
        .supply-fill.yellow { background: #ffeb3b; }
        .supply-fill.black { background: #333; }
        .supply-item { margin-bottom: 16px; }
        .supply-item:last-child { margin-bottom: 0; }
        .supply-label { display: flex; justify-content: space-between; font-size: 13px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <div class="xerox-logo">
            <span class="xerox-text">XEROX</span>
        </div>
        <div class="user-info">Logged in as: admin</div>
    </div>
    <div class="nav">
        <a href="#" class="active">Status</a>
        <a href="#">Jobs</a>
        <a href="#">Print</a>
        <a href="#">Address Book</a>
        <a href="#">Properties</a>
        <a href="#">Support</a>
    </div>
    <div class="content">
        <div class="success-banner">
            <strong>Login Successful!</strong><br>
            You have authenticated to the Xerox WorkCentre. This is a demo for Brutus AI browser automation with vendor defaults (admin/1111).
        </div>
        <div class="grid">
            <div class="card">
                <div class="card-header">Device Information</div>
                <div class="card-body">
                    <div class="info-row"><span class="info-label">Model</span><span class="info-value">WorkCentre 7855</span></div>
                    <div class="info-row"><span class="info-label">Serial Number</span><span class="info-value">XRX987654321</span></div>
                    <div class="info-row"><span class="info-label">System Software</span><span class="info-value">073.040.075.09100</span></div>
                    <div class="info-row"><span class="info-label">IP Address</span><span class="info-value">10.0.0.75</span></div>
                    <div class="info-row"><span class="info-label">Status</span><span class="info-value" style="color: #4caf50;">Ready</span></div>
                </div>
            </div>
            <div class="card">
                <div class="card-header">Supplies Status</div>
                <div class="card-body">
                    <div class="supply-item">
                        <div class="supply-label"><span>Cyan Toner</span><span>85%%</span></div>
                        <div class="supply-bar"><div class="supply-fill cyan" style="width: 85%%;"></div></div>
                    </div>
                    <div class="supply-item">
                        <div class="supply-label"><span>Magenta Toner</span><span>72%%</span></div>
                        <div class="supply-bar"><div class="supply-fill magenta" style="width: 72%%;"></div></div>
                    </div>
                    <div class="supply-item">
                        <div class="supply-label"><span>Yellow Toner</span><span>91%%</span></div>
                        <div class="supply-bar"><div class="supply-fill yellow" style="width: 91%%;"></div></div>
                    </div>
                    <div class="supply-item">
                        <div class="supply-label"><span>Black Toner</span><span>68%%</span></div>
                        <div class="supply-bar"><div class="supply-fill black" style="width: 68%%;"></div></div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-header">Usage Counters</div>
                <div class="card-body">
                    <div class="info-row"><span class="info-label">Total Impressions</span><span class="info-value">247,893</span></div>
                    <div class="info-row"><span class="info-label">Color Impressions</span><span class="info-value">89,234</span></div>
                    <div class="info-row"><span class="info-label">B&W Impressions</span><span class="info-value">158,659</span></div>
                    <div class="info-row"><span class="info-label">Copies Made</span><span class="info-value">45,122</span></div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>`

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getSession(r *http.Request) string {
	cookie, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	return sessions[cookie.Value]
}

func setSession(w http.ResponseWriter, user string) {
	sessionID := generateSessionID()
	sessionsMu.Lock()
	sessions[sessionID] = user
	sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: sessionID,
		Path:  "/",
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Xerox_WorkCentre")
	w.Header().Set("X-Xerox-Device", "WorkCentre 7855")

	if getSession(r) != "" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, loginPage, "none")
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Xerox_WorkCentre")

	if getSession(r) == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardPage)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "Xerox_WorkCentre")

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	r.ParseForm()
	username := r.FormValue("webUIuserName")
	password := r.FormValue("webUIpasswd")

	if username == validUser && password == validPass {
		setSession(w, username)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Login failed - show error
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, loginPage, "block")
}

func main() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/index.html", indexHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/properties/authentication/luidLogin.php", loginHandler)

	log.Printf("Xerox WorkCentre mock running on port %s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
