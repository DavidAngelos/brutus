// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Package snmp provides SNMP community string testing for Brutus.
//
// Community strings are organized into tiers based on prevalence and value:
//   - Default (25): Universal defaults with highest hit rate
//   - Extended (75): Adds vendor-specific and common variations
//   - Full (200+): Comprehensive database including legacy and obscure defaults
package snmp

// Tier represents a community string wordlist tier.
type Tier string

const (
	TierDefault  Tier = "default"
	TierExtended Tier = "extended"
	TierFull     Tier = "full"
)

// DefaultCommunityStrings - Top 25 most common (highest hit rate)
// These are found on a significant percentage of misconfigured devices.
var DefaultCommunityStrings = []string{
	// Universal defaults (found on 50%+ of vulnerable devices)
	"public",    // RFC 1157 default read-only - nearly universal
	"private",   // RFC 1157 default read-write
	"community", // Generic community string

	// Common lazy defaults
	"snmp",
	"default",
	"password",
	"admin",
	"manager",
	"root",
	"test",
	"guest",

	// High-value vendor defaults (often unchanged)
	"cisco",        // Cisco networking equipment
	"CISCO",        // Case variant
	"cable-docsis", // Cable modems (DOCSIS standard)
	"apc",          // APC UPS systems
	"hp_admin",     // HP printers and switches
	"netman",       // Network management systems

	// Access level variants
	"read",
	"write",
	"monitor",
	"secret",

	// IPMI/BMC (server management - HIGH VALUE)
	"ADMIN",    // Supermicro IPMI default
	"PASSW0RD", // Dell iDRAC older versions
}

// ExtendedCommunityStrings - Top 75 (includes DefaultCommunityStrings)
// Adds vendor-specific defaults and common patterns.
var ExtendedCommunityStrings = []string{
	// === DEFAULT TIER (1-25) ===
	"public", "private", "community", "snmp", "default",
	"password", "admin", "manager", "root", "test",
	"guest", "cisco", "CISCO", "cable-docsis", "apc",
	"hp_admin", "netman", "read", "write", "monitor",
	"secret", "ADMIN", "PASSW0RD",

	// === NETWORKING EQUIPMENT ===
	// Cisco
	"c",        // Cisco abbreviated
	"san-fran", // Cisco example configs

	// HP/Aruba
	"HP",
	"procurve",
	"aruba",
	"aruba123",

	// Juniper
	"juniper",
	"JUNIPER",

	// Fortinet
	"fortinet",
	"fortigate",

	// Palo Alto
	"paloalto",

	// Ubiquiti
	"ubnt",
	"ubiquiti",

	// MikroTik
	"mikrotik",

	// 3Com (legacy but still found)
	"3com",
	"3Com",

	// Brocade/Ruckus
	"brocade",
	"ruckus",

	// === SERVER MANAGEMENT (IPMI/BMC) ===
	// Dell iDRAC
	"calvin", // Dell iDRAC default
	"Dell",
	"idrac",

	// Supermicro
	"supermicro",
	"SUPERMICRO",

	// HP iLO
	"ilo",
	"iLO",
	"hpinvent",

	// IBM/Lenovo IMM
	"ibm",
	"IBM",
	"lenovo",
	"imm",
	"USERID",

	// === PRINTERS ===
	"xerox",
	"XEROX",
	"canon",
	"canon_admin",
	"ricoh",
	"brother",
	"epson",
	"kyocera",
	"konica",
	"lexmark",
	"samsung",

	// === CABLE/DSL MODEMS ===
	"cable-d",
	"motorola",
	"arris",
	"ARRIS",
	"surfboard",

	// === ACCESS CONTROL ===
	"read-only",
	"read-write",
	"readwrite",
	"ro",
	"rw",
}

// FullCommunityStrings - Comprehensive database (200+)
// All known community strings including legacy, regional, and obscure defaults.
var FullCommunityStrings = []string{
	// === EXTENDED TIER (1-75) - included above ===
	"public", "private", "community", "snmp", "default",
	"password", "admin", "manager", "root", "test",
	"guest", "cisco", "CISCO", "cable-docsis", "apc",
	"hp_admin", "netman", "read", "write", "monitor",
	"secret", "ADMIN", "PASSW0RD", "c", "san-fran",
	"HP", "procurve", "aruba", "aruba123", "juniper",
	"JUNIPER", "fortinet", "fortigate", "paloalto", "ubnt",
	"ubiquiti", "mikrotik", "3com", "3Com", "brocade",
	"ruckus", "calvin", "Dell", "idrac", "supermicro",
	"SUPERMICRO", "ilo", "iLO", "hpinvent", "ibm",
	"IBM", "lenovo", "imm", "USERID", "xerox",
	"XEROX", "canon", "canon_admin", "ricoh", "brother",
	"epson", "kyocera", "konica", "lexmark", "samsung",
	"cable-d", "motorola", "arris", "ARRIS", "surfboard",
	"read-only", "read-write", "readwrite", "ro", "rw",

	// === IP CAMERAS / DVR / NVR ===
	"hikvision",
	"HIKVISION",
	"dahua",
	"DAHUA",
	"axis",
	"AXIS",
	"foscam",
	"amcrest",
	"reolink",
	"vivotek",
	"hanwha",
	"uniview",
	"geovision",
	"avigilon",
	"pelco",
	"bosch",
	"honeywell",
	"dvr",
	"nvr",
	"camera",
	"video",
	"surveillance",

	// === INDUSTRIAL / SCADA / ICS ===
	"schneider",
	"SCHNEIDER",
	"siemens",
	"SIEMENS",
	"rockwell",
	"allen-bradley",
	"ALLEN-BRADLEY",
	"modicon",
	"plc",
	"PLC",
	"scada",
	"SCADA",
	"ics",
	"automation",
	"control",
	"factory",
	"TENmanUFactOryPOWER", // Known vulnerable on some industrial equipment
	"ABB",
	"abb",
	"emerson",
	"yokogawa",
	"mitsubishi",
	"omron",
	"fanuc",
	"ge",
	"GE",

	// === UPS / PDU / POWER ===
	"APC",
	"apcuser",
	"eaton",
	"EATON",
	"liebert",
	"LIEBERT",
	"tripplite",
	"tripp",
	"cyberpower",
	"ups",
	"UPS",
	"pdu",
	"PDU",
	"power",

	// === NAS / STORAGE ===
	"synology",
	"qnap",
	"QNAP",
	"netgear",
	"NETGEAR",
	"readynas",
	"buffalo",
	"drobo",
	"nas",
	"NAS",
	"storage",
	"backup",

	// === CONSUMER ROUTERS ===
	"linksys",
	"LINKSYS",
	"dlink",
	"D-Link",
	"tplink",
	"TP-LINK",
	"asus",
	"ASUS",
	"belkin",
	"zyxel",
	"ZyXEL",
	"netis",
	"tenda",
	"huawei",
	"HUAWEI",

	// === WIRELESS ACCESS POINTS ===
	"wireless",
	"wifi",
	"wlan",
	"access",
	"accesspoint",
	"ap",

	// === VoIP / TELEPHONY ===
	"polycom",
	"POLYCOM",
	"cisco-voice",
	"avaya",
	"AVAYA",
	"mitel",
	"yealink",
	"grandstream",
	"sip",
	"voip",
	"phone",

	// === LEGACY / KNOWN VULNERABLE ===
	"OrigEquipMfr", // OEM default
	"CR52401",      // Known vulnerable serial-like
	"0392a0",       // Hex pattern
	"NoGaH$@!",     // Special chars
	"xyzzy",        // Adventure game reference (found in old equipment)
	"freekevin",    // Kevin Mitnick reference
	"volition",     // Legacy networking
	"xyplex",       // Terminal servers
	"Intermec",     // Industrial equipment
	"bintec",       // Bintec routers
	"openview",     // HP OpenView
	"tivoli",       // IBM Tivoli
	"tiv0li",       // Obfuscated variant
	"sun",          // Sun/Oracle
	"SUN",
	"solaris",

	// === MANAGEMENT SOFTWARE ===
	"snmpd",
	"net-snmp",
	"agent",
	"agentx",
	"master",
	"trap",
	"snmptrap",
	"SNMP_trap",
	"rmon",
	"rmon_admin",

	// === REGIONAL VARIANTS ===
	// Spanish/Portuguese
	"publico",
	"privado",
	// German
	"oeffentlich",
	"privat",
	// French
	"publique",
	"prive",
	// Norwegian/Swedish
	"offentlig",

	// === NUMERIC / PATTERN ===
	"0",
	"1",
	"123",
	"1234",
	"12345",
	"123456",
	"111111",
	"000000",
	"admin123",
	"snmp123",
	"test123",
	"pass123",

	// === GENERIC / COMMON WORDS ===
	"system",
	"SYSTEM",
	"security",
	"SECURITY",
	"network",
	"NETWORK",
	"internal",
	"external",
	"local",
	"remote",
	"core",
	"edge",
	"mgmt",
	"management",
	"config",
	"configuration",
	"diag",
	"debug",
	"enable",
	"disable",
	"all",
	"any",
	"ANY",
	"none",
	"anonymous",
	"user",
	"operator",
	"tech",
	"support",
	"service",
	"maintenance",
	"field",
	"installer",

	// === CASE VARIANTS OF COMMON ===
	"PUBLIC",
	"PRIVATE",
	"COMMUNITY",
	"SNMP",
	"DEFAULT",
	"PASSWORD",
	"MANAGER",
	"ROOT",
	"TEST",
	"GUEST",
	"Admin",
	"Public",
	"Private",

	// === EMPTY / SPECIAL ===
	"",  // Empty string (some devices accept this)
	" ", // Single space
	"null",
	"NULL",
	"undefined",
}

// GetCommunityStrings returns the community strings for the specified tier.
func GetCommunityStrings(tier Tier) []string {
	switch tier {
	case TierDefault:
		return DefaultCommunityStrings
	case TierExtended:
		return ExtendedCommunityStrings
	case TierFull:
		return FullCommunityStrings
	default:
		return DefaultCommunityStrings
	}
}

// ValidateTier checks if a tier string is valid.
func ValidateTier(tier string) bool {
	switch Tier(tier) {
	case TierDefault, TierExtended, TierFull:
		return true
	default:
		return false
	}
}
