// Copyright 2026 Praetorian Security, Inc.
// SPDX-License-Identifier: Apache-2.0

package browser

// LoginErrorPatterns contains text patterns indicating login failure.
// UNION of patterns from browser.go and verification.go.
// All patterns are lowercase for case-insensitive matching.
var LoginErrorPatterns = []string{
	// Password errors
	"invalid password",
	"incorrect password",
	"wrong password",

	// Credential errors
	"invalid credentials",
	"incorrect credentials",
	"bad credentials",

	// Authentication errors
	"authentication failed",
	"login failed",
	"access denied",

	// User errors
	"invalid username",
	"user not found",

	// Prompt indicators
	"try again",
	// NOTE: "please enter" removed - too generic, catches normal form instructions

	// CSS/HTML patterns (from verification.go)
	`class="error"`,
	`class='error'`,
	`id="error"`,
}

// LoginSuccessPatterns contains text patterns indicating successful login.
// UNION of patterns from browser.go successPatterns and verification.go successIndicators.
// All patterns are lowercase for case-insensitive matching.
var LoginSuccessPatterns = []string{
	// Logout indicators
	"logout",
	"log out",
	"sign out",
	"signout",

	// Dashboard/welcome
	"dashboard",
	"welcome",
	"logged in", // from verification.go

	// Configuration/settings
	"configuration",
	"settings",

	// Account/profile
	"my account", // from verification.go
	"profile",    // added for completeness

	// Status/admin
	"status",
	"device status", // from browser.go
	"system status", // from verification.go
	"admin panel",
	"control panel",
}

// URLSuccessPaths contains URL path segments indicating successful login.
// From verification.go successPaths.
var URLSuccessPaths = []string{
	"/dashboard",
	"/admin",
	"/home",
	"/main",
	"/index",
	"/welcome",
	"/console",
	"/panel",
	"/status",
	"/settings",
	"/config",
}
