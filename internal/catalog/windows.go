package catalog

import (
	"fmt"
	"strings"
)

// The Windows catalogue. A Windows device cannot be enrolled yet, so nothing
// here is delivered to anything; the settings are stored with the policy and
// will be sent when a Windows device can be enrolled. Each Path is the
// configuration service provider (CSP) address Windows' own management uses,
// and Note says so on the page, so nobody believes a laptop is being held to a
// policy it has never been given.

const winNote = "Stored now; applied when a Windows device can be enrolled."

func httpsURL(s string) error {
	if !strings.HasPrefix(s, "https://") || strings.ContainsAny(s, " \t") {
		return fmt.Errorf("this must be a web address starting with https://")
	}
	return nil
}

func init() {
	const (
		pw   = "Sign-in and lock screen"
		enc  = "Encryption and security"
		dev  = "Device features"
		scr  = "Desktop and display"
		upd  = "Updates"
		priv = "Privacy"
	)
	const csp = "./Device/Vendor/MSFT/"
	add(
		Setting{Key: "windows.password_required", OS: "windows", Section: pw, Label: "Require a sign-in password",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/DeviceLock/DevicePasswordEnabled", Note: winNote},
		Setting{Key: "windows.password_min_length", OS: "windows", Section: pw, Label: "Shortest password",
			Kind: Int, Merge: Highest, Min: 4, Max: 32, Unit: "characters", Path: csp + "Policy/Config/DeviceLock/MinDevicePasswordLength", Note: winNote},
		Setting{Key: "windows.password_complexity", OS: "windows", Section: pw, Label: "Kinds of character required",
			Help: "How many of lower case, upper case, digits and symbols a password must mix.",
			Kind: Int, Merge: Highest, Min: 1, Max: 4, Unit: "kinds", Path: csp + "Policy/Config/DeviceLock/MinDevicePasswordComplexCharacters", Note: winNote},
		Setting{Key: "windows.password_expiry_days", OS: "windows", Section: pw, Label: "Password must change every",
			Kind: Int, Merge: Lowest, Min: 1, Max: 730, Unit: "days", Path: csp + "Policy/Config/DeviceLock/DevicePasswordExpiration", Note: winNote},
		Setting{Key: "windows.password_history", OS: "windows", Section: pw, Label: "Passwords that cannot be reused",
			Kind: Int, Merge: Highest, Min: 1, Max: 24, Unit: "passwords", Path: csp + "Policy/Config/DeviceLock/DevicePasswordHistory", Note: winNote},
		Setting{Key: "windows.lock_after_failures", OS: "windows", Section: pw, Label: "Lock the device after wrong passwords",
			Kind: Int, Merge: Lowest, Min: 1, Max: 999, Unit: "tries", Path: csp + "Policy/Config/DeviceLock/MaxDevicePasswordFailedAttempts", Note: winNote},
		Setting{Key: "windows.screen_lock_minutes", OS: "windows", Section: pw, Label: "Lock the screen after",
			Kind: Int, Merge: Lowest, Min: 1, Max: 999, Unit: "minutes", Path: csp + "Policy/Config/DeviceLock/MaxInactivityTimeDeviceLock", Note: winNote},

		Setting{Key: "windows.bitlocker_required", OS: "windows", Section: enc, Label: "Encrypt the disk (BitLocker)",
			Kind: Bool, Merge: Restrictive, Path: csp + "BitLocker/RequireDeviceEncryption", Note: winNote},
		Setting{Key: "windows.firewall_on", OS: "windows", Section: enc, Label: "Keep the firewall on",
			Help: "On for the domain, private and public networks.",
			Kind: Bool, Merge: Restrictive, Path: csp + "Firewall/MdmStore/{DomainProfile,PrivateProfile,PublicProfile}/EnableFirewall", Note: winNote},
		Setting{Key: "windows.defender_realtime", OS: "windows", Section: enc, Label: "Keep virus protection (Defender) running",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/Defender/AllowRealtimeMonitoring", Note: winNote},
		Setting{Key: "windows.smartscreen", OS: "windows", Section: enc, Label: "Warn about dangerous websites and downloads",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/SmartScreen/EnableSmartScreenInShell", Note: winNote},

		Setting{Key: "windows.camera_blocked", OS: "windows", Section: dev, Label: "Block the camera",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/Camera/AllowCamera", Note: winNote},
		Setting{Key: "windows.usb_storage_blocked", OS: "windows", Section: dev, Label: "Block writing to USB sticks and external disks",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/Storage/RemovableDiskDenyWriteAccess", Note: winNote},
		Setting{Key: "windows.bluetooth_blocked", OS: "windows", Section: dev, Label: "Block Bluetooth",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/Connectivity/AllowBluetooth", Note: winNote},
		Setting{Key: "windows.store_blocked", OS: "windows", Section: dev, Label: "Block the Microsoft Store",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/ApplicationManagement/AllowStore", Note: winNote},
		Setting{Key: "windows.screenshots_blocked", OS: "windows", Section: dev, Label: "Block screenshots",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/Experience/AllowScreenCapture", Note: winNote},

		Setting{Key: "windows.desktop_background_url", OS: "windows", Section: scr, Label: "Desktop background picture",
			Help: "A web address (https://) of a picture. Every device gets it as its desktop background. Needs Windows Enterprise or Education.",
			Kind: Text, Merge: FirstByName, Path: csp + "Personalization/DesktopImageUrl", Check: httpsURL, Note: winNote},
		Setting{Key: "windows.lock_screen_image_url", OS: "windows", Section: scr, Label: "Lock screen picture",
			Help: "A web address (https://) of a picture shown on the lock screen. Needs Windows Enterprise or Education.",
			Kind: Text, Merge: FirstByName, Path: csp + "Personalization/LockScreenImageUrl", Check: httpsURL, Note: winNote},

		Setting{Key: "windows.update_mode", OS: "windows", Section: upd, Label: "How Windows updates",
			Kind: Choice, Merge: Strictest, Path: csp + "Policy/Config/Update/AllowAutoUpdate", Note: winNote,
			Options: []Option{
				{"0", "Tell the person, and let them choose"},
				{"1", "Install automatically, and tell the person to restart"},
				{"3", "Install automatically, restart at a set time"},
				{"4", "Install and restart with no choice for the person"},
			}},
		Setting{Key: "windows.defer_feature_days", OS: "windows", Section: upd, Label: "Wait before big Windows updates",
			Kind: Int, Merge: Highest, Min: 0, Max: 365, Unit: "days", Path: csp + "Policy/Config/Update/DeferFeatureUpdatesPeriodInDays", Note: winNote},
		Setting{Key: "windows.defer_quality_days", OS: "windows", Section: upd, Label: "Wait before monthly fixes",
			Kind: Int, Merge: Highest, Min: 0, Max: 30, Unit: "days", Path: csp + "Policy/Config/Update/DeferQualityUpdatesPeriodInDays", Note: winNote},

		Setting{Key: "windows.telemetry", OS: "windows", Section: priv, Label: "What Windows reports to Microsoft",
			Kind: Choice, Merge: Strictest, Path: csp + "Policy/Config/System/AllowTelemetry", Note: winNote,
			Options: []Option{
				{"3", "Full"},
				{"2", "Enhanced"},
				{"1", "Required only"},
				{"0", "Security only"},
			}},
		Setting{Key: "windows.location_blocked", OS: "windows", Section: priv, Label: "Block location services",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/System/AllowLocation", Note: winNote},
		Setting{Key: "windows.cortana_blocked", OS: "windows", Section: priv, Label: "Block the Cortana assistant",
			Kind: Bool, Merge: Restrictive, Path: csp + "Policy/Config/Experience/AllowCortana", Note: winNote},
	)
}
