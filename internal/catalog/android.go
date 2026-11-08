package catalog

import (
	"fmt"
	"strconv"
	"strings"
)

// The Android catalogue. Every Path is a field of Google's Android Management
// API policy resource, written from the API's reference. Two things are true
// of all of them and are said on the page rather than hidden: some fields
// reach only a fully managed (company) phone and some only a work profile,
// and Google has minimum Android versions for several. Google refuses a
// policy it does not accept, and a policy Google refuses is a policy that was
// not saved, so a field a phone cannot honour is found when the policy is
// saved and not later.

func plain(v any) (any, bool) { return v, true }

// on sends a constant when the switch is on, and nothing when it is off.
func on(c any) func(any) (any, bool) {
	return func(v any) (any, bool) { b, _ := v.(bool); return c, b }
}

// millis turns seconds into the string of milliseconds Google wants.
func millis(v any) (any, bool) { return strconv.Itoa(v.(int) * 1000), true }

// days turns days into Google's duration string, in seconds.
func days(v any) (any, bool) { return fmt.Sprintf("%ds", v.(int)*86400), true }

func nonEmpty(v any) (any, bool) { s, _ := v.(string); return s, s != "" }

func emailAddress(s string) error {
	at := strings.Index(s, "@")
	if at < 1 || at != strings.LastIndex(s, "@") || !strings.Contains(s[at:], ".") || strings.ContainsAny(s, " \t,;<>") {
		return fmt.Errorf("that is not an email address")
	}
	return nil
}

func packageName(s string) error {
	if !packageRE.MatchString(s) {
		return fmt.Errorf("that is not an app's package name (like com.example.vpn)")
	}
	return nil
}

func init() {
	const (
		pw   = "Password and lock screen"
		scr  = "Screen and display"
		dev  = "Device features"
		net  = "Network"
		apps = "Apps"
		upd  = "Updates"
		wp   = "Personal phones (work profile)"
		msg  = "Messages on the phone"
	)
	add(
		// ---------------------------------------------------- password
		Setting{Key: "android.password_quality", OS: "android", Section: pw, Label: "What kind of lock",
			Help: "The weakest lock a phone may use. Later choices are stricter.",
			Kind: Choice, Merge: Strictest, Path: "passwordRequirements.passwordQuality", Send: plain,
			Options: []Option{
				{"SOMETHING", "Any lock (pattern, PIN or password)"},
				{"NUMERIC", "A numeric PIN"},
				{"NUMERIC_COMPLEX", "A PIN with no repeated or ordered digits"},
				{"ALPHABETIC", "A password with letters"},
				{"ALPHANUMERIC", "A password with letters and numbers"},
				{"COMPLEX", "A complex password"},
			}},
		Setting{Key: "android.password_min_length", OS: "android", Section: pw, Label: "Shortest passcode",
			Help: "The fewest characters a passcode may have.",
			Kind: Int, Merge: Highest, Min: 4, Max: 64, Unit: "characters", Path: "passwordRequirements.passwordMinimumLength", Send: plain},
		Setting{Key: "android.password_history", OS: "android", Section: pw, Label: "Passcodes that cannot be reused",
			Help: "How many of the last passcodes a person may not pick again.",
			Kind: Int, Merge: Highest, Min: 1, Max: 50, Unit: "passcodes", Path: "passwordRequirements.passwordHistoryLength", Send: plain},
		Setting{Key: "android.password_expiry_days", OS: "android", Section: pw, Label: "Passcode must change every",
			Help: "After this many days the phone asks for a new passcode.",
			Kind: Int, Merge: Lowest, Min: 1, Max: 730, Unit: "days", Path: "passwordRequirements.passwordExpirationTimeout", Send: days},
		Setting{Key: "android.wipe_after_failures", OS: "android", Section: pw, Label: "Erase after wrong passcodes",
			Help: "After this many wrong tries in a row the phone is erased (a work profile phone loses only the work profile). Set it with care: a child with a phone can trigger it.",
			Kind: Int, Merge: Lowest, Min: 3, Max: 100, Unit: "tries", Path: "passwordRequirements.maximumFailedPasswordsForWipe", Send: plain},
		Setting{Key: "android.screen_lock_seconds", OS: "android", Section: pw, Label: "Lock the screen after",
			Help: "The longest a phone may sit unused before the screen locks.",
			Kind: Int, Merge: Lowest, Min: 15, Max: 3600, Unit: "seconds", Path: "maximumTimeToLock", Send: millis},
		Setting{Key: "android.encryption_required", OS: "android", Section: pw, Label: "Encrypt the phone",
			Help: "Requires the phone's storage to be encrypted, protected by the lock.",
			Kind: Bool, Merge: Restrictive, Path: "encryptionPolicy", Send: on("ENABLED_WITH_PASSWORD")},

		// ------------------------------------------------------ screen
		Setting{Key: "android.wallpaper_locked", OS: "android", Section: scr, Label: "Lock the wallpaper",
			Help: "People cannot change the background picture.",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "setWallpaperDisabled", Send: on(true)},
		Setting{Key: "android.screenshots_blocked", OS: "android", Section: scr, Label: "Block screenshots and screen recording",
			Help: "Nobody can capture the screen. In a work profile this covers work apps only.",
			Kind: Bool, Merge: Restrictive, Path: "screenCaptureDisabled", Send: on(true)},
		Setting{Key: "android.volume_locked", OS: "android", Section: scr, Label: "Lock the volume",
			Help: "People cannot change the volume.",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "adjustVolumeDisabled", Send: on(true)},
		Setting{Key: "android.status_bar_disabled", OS: "android", Section: scr, Label: "Hide the notification bar",
			Help: "Removes the pull-down bar. Meant for single-purpose phones.",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "statusBarDisabled", Send: on(true)},

		// ------------------------------------------------------ device
		Setting{Key: "android.camera_disabled", OS: "android", Section: dev, Label: "Block the camera",
			Help: "No app can use the camera. In a work profile this covers work apps only.",
			Kind: Bool, Merge: Restrictive, Path: "cameraDisabled", Send: on(true)},
		Setting{Key: "android.bluetooth_disabled", OS: "android", Section: dev, Label: "Block Bluetooth",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "bluetoothDisabled", Send: on(true)},
		Setting{Key: "android.usb_transfer_blocked", OS: "android", Section: dev, Label: "Block copying files over USB",
			Help: "Stops a phone plugged into a computer from handing over its files.",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "usbFileTransferDisabled", Send: on(true)},
		Setting{Key: "android.external_media_blocked", OS: "android", Section: dev, Label: "Block memory cards and USB sticks",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "mountPhysicalMediaDisabled", Send: on(true)},
		Setting{Key: "android.outgoing_calls_blocked", OS: "android", Section: dev, Label: "Block outgoing calls",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "outgoingCallsDisabled", Send: on(true)},
		Setting{Key: "android.sms_blocked", OS: "android", Section: dev, Label: "Block text messages",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "smsDisabled", Send: on(true)},
		Setting{Key: "android.location_sharing_blocked", OS: "android", Section: dev, Label: "Block sharing location",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "shareLocationDisabled", Send: on(true)},
		Setting{Key: "android.factory_reset_blocked", OS: "android", Section: dev, Label: "Block factory reset by the person",
			Help: "Stops a person wiping the phone from its settings to get past the company's rules.",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "factoryResetDisabled", Send: on(true)},
		Setting{Key: "android.safe_boot_blocked", OS: "android", Section: dev, Label: "Block safe mode",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "safeBootDisabled", Send: on(true)},
		Setting{Key: "android.add_user_blocked", OS: "android", Section: dev, Label: "Block extra user accounts on the phone",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "addUserDisabled", Send: on(true)},
		Setting{Key: "android.remove_user_blocked", OS: "android", Section: dev, Label: "Block removing user accounts",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "removeUserDisabled", Send: on(true)},
		Setting{Key: "android.accounts_locked", OS: "android", Section: dev, Label: "Block adding or removing accounts",
			Help: "People cannot add their own Google or email accounts.",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "modifyAccountsDisabled", Send: on(true)},
		Setting{Key: "android.untrusted_apps_blocked", OS: "android", Section: dev, Label: "Block apps from outside the Play Store",
			Help: "No installing apps from files or websites.",
			Kind: Bool, Merge: Restrictive, Path: "advancedSecurityOverrides.untrustedAppsPolicy", Send: on("DISALLOW_INSTALL")},
		Setting{Key: "android.play_protect_required", OS: "android", Section: dev, Label: "Require Google Play Protect",
			Help: "Google's app scanning must stay on. People cannot switch it off.",
			Kind: Bool, Merge: Restrictive, Path: "advancedSecurityOverrides.googlePlayProtectVerifyApps", Send: on("VERIFY_APPS_ENFORCED")},
		Setting{Key: "android.auto_time_required", OS: "android", Section: dev, Label: "Force automatic date, time and time zone",
			Help: "People cannot set the clock by hand, which matters for certificates and for the audit trail.",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "autoDateAndTimeZone", Send: on("AUTO_DATE_AND_TIME_ZONE_ENFORCED")},
		Setting{Key: "android.backup_blocked", OS: "android", Section: dev, Label: "Block cloud backup of the phone",
			Help: "Stops the phone's data being backed up to a personal Google account.",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "backupServiceEnabled", Send: func(v any) (any, bool) { b, _ := v.(bool); return false, b }},
		Setting{Key: "android.frp_accounts", OS: "android", Section: dev, Label: "Accounts that can recover a reset phone",
			Help: "Factory reset protection: after a reset outside the company's control, only these Google accounts can set the phone up again. One email address a line. Without it a reset phone can be locked to nobody.",
			Kind: List, Merge: Union, Max: 10, Path: "frpAdminEmails", Send: plain, For: "company", Check: emailAddress},
		Setting{Key: "android.accessibility_system_only", OS: "android", Section: dev, Label: "Allow only Android's own accessibility services",
			Help: "Other accessibility apps can read and control everything on the screen, so they are a way to take over a phone. This blocks all of them. It also blocks third-party screen readers people may depend on, so check before turning it on.",
			Kind: Bool, Merge: Restrictive, Path: "permittedAccessibilityServices.packageNames", Send: plain},
		Setting{Key: "android.accessibility_allowed", OS: "android", Section: dev, Label: "Accessibility apps that are allowed",
			Help: "Only these accessibility apps (plus Android's own) can run. One package name a line. Ignored if the box above is ticked.",
			Kind: List, Merge: Intersect, Max: 50, Path: "permittedAccessibilityServices.packageNames", Send: plain, Check: packageName},
		Setting{Key: "android.debugging_blocked", OS: "android", Section: dev, Label: "Block developer debugging",
			Help: "Stops USB debugging, which can be used to pull data off a phone.",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "debuggingFeaturesAllowed", Send: func(v any) (any, bool) { b, _ := v.(bool); return false, b }},
		Setting{Key: "android.printing_blocked", OS: "android", Section: dev, Label: "Block printing",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "printingPolicy", Send: on("PRINTING_DISALLOWED")},

		// ------------------------------------------------------ network
		Setting{Key: "android.wifi_locked", OS: "android", Section: net, Label: "Block changing Wi-Fi settings",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "wifiConfigDisabled", Send: on(true)},
		Setting{Key: "android.tethering_blocked", OS: "android", Section: net, Label: "Block sharing the phone's internet (hotspot)",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "tetheringConfigDisabled", Send: on(true)},
		Setting{Key: "android.vpn_locked", OS: "android", Section: net, Label: "Block changing VPN settings",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "vpnConfigDisabled", Send: on(true)},
		Setting{Key: "android.mobile_networks_locked", OS: "android", Section: net, Label: "Block changing mobile network settings",
			Kind: Bool, Merge: Restrictive, For: "company", Path: "mobileNetworksConfigDisabled", Send: on(true)},
		Setting{Key: "android.always_on_vpn_app", OS: "android", Section: net, Label: "Always-on VPN app",
			Help: "The package name of the VPN app that stays connected, such as com.example.vpn. The app must already be on the phone (add it under Apps as required).",
			Kind: Text, Merge: FirstByName, Path: "alwaysOnVpnPackage.packageName", Send: nonEmpty, Check: packageName},
		Setting{Key: "android.always_on_vpn_lockdown", OS: "android", Section: net, Label: "Block the internet when the VPN is off",
			Kind: Bool, Merge: Restrictive, Path: "alwaysOnVpnPackage.lockdownEnabled", Send: on(true)},

		// -------------------------------------------------------- apps
		Setting{Key: "android.apps", OS: "android", Section: apps, Label: "Apps to push, offer or block",
			Help: "Required apps are installed on the phone for the person. Available apps are offered in the managed Play Store. Blocked apps are kept off. Each line is an app's package name and what to do.",
			Kind: Apps, Merge: Combine, Path: "applications"},
		Setting{Key: "android.play_store_mode", OS: "android", Section: apps, Label: "Who may install apps",
			Help: "Open: people install anything that is not blocked. Approved only: people install only the apps listed above as required or available.",
			Kind: Choice, Merge: Strictest, Path: "playStoreMode", Send: plain,
			Options: []Option{
				{"BLACKLIST", "Anything that is not blocked"},
				{"WHITELIST", "Approved apps only"},
			}},
		Setting{Key: "android.default_permission", OS: "android", Section: apps, Label: "When an app asks for a permission",
			Kind: Choice, Merge: Strictest, Path: "defaultPermissionPolicy", Send: plain,
			Options: []Option{
				{"GRANT", "Allow it without asking"},
				{"PROMPT", "Ask the person"},
				{"DENY", "Refuse it"},
			}},
		Setting{Key: "android.app_updates", OS: "android", Section: apps, Label: "Updating apps",
			Kind: Choice, Merge: Strictest, Path: "appAutoUpdatePolicy", Send: plain,
			Options: []Option{
				{"NEVER", "Never update automatically"},
				{"CHOICE_TO_THE_USER", "The person chooses"},
				{"WIFI_ONLY", "Update on Wi-Fi only"},
				{"ALWAYS", "Always update"},
			}},

		// ---------------------------------------------------- updates
		Setting{Key: "android.system_updates", OS: "android", Section: upd, Label: "Updating Android itself",
			Help: "Automatic installs system updates as soon as they arrive. Postponed holds them back for up to 30 days.",
			Kind: Choice, Merge: Strictest, For: "company", Path: "systemUpdate.type", Send: plain,
			Options: []Option{
				{"POSTPONE", "Postpone (up to 30 days)"},
				{"AUTOMATIC", "Automatic"},
			}},

		// ---------------------------------------------- work profile
		Setting{Key: "android.block_copy_to_personal", OS: "android", Section: wp, Label: "Block copying from work apps to personal apps",
			Help: "Text copied in a work app cannot be pasted in a personal one.",
			Kind: Bool, Merge: Restrictive, For: "personal", Path: "crossProfilePolicies.crossProfileCopyPaste", Send: on("COPY_FROM_WORK_TO_PERSONAL_DISALLOWED")},
		Setting{Key: "android.block_sharing_to_personal", OS: "android", Section: wp, Label: "Block sharing from work apps to personal apps",
			Help: "Work files and links cannot be sent to personal apps. Sharing the other way, from personal to work, stays allowed.",
			Kind: Bool, Merge: Restrictive, For: "personal", Path: "crossProfilePolicies.crossProfileDataSharing", Send: on("DATA_SHARING_FROM_WORK_TO_PERSONAL_DISALLOWED")},

		// ------------------------------------------------- messages
		Setting{Key: "android.lock_screen_message", OS: "android", Section: msg, Label: "Text on the lock screen",
			Help: "Shown on the lock screen of a company phone, for example \"Property of Kalesi Foods. If found, call 0800 000 0000.\"",
			Kind: Text, Merge: FirstByName, For: "company", Path: "deviceOwnerLockScreenInfo.defaultMessage", Send: nonEmpty},
		Setting{Key: "android.short_message", OS: "android", Section: msg, Label: "Short message on the settings screen",
			Help: "Shown where the phone says it is managed, such as \"Managed by Kalesi Foods. Call 0800 000 0000 for help.\"",
			Kind: Text, Merge: FirstByName, Path: "shortSupportMessage.defaultMessage", Send: nonEmpty},
		Setting{Key: "android.long_message", OS: "android", Section: msg, Label: "Longer message for the person",
			Kind: Text, Merge: FirstByName, Path: "longSupportMessage.defaultMessage", Send: nonEmpty},
	)
}
