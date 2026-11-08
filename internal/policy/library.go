package policy

import "encoding/json"

// The library: ready-made policies for each operating system, switched on
// with one click and then edited like any other. They exist so an
// administrator starts from something a careful person would write, and sees
// what each system can do, instead of facing an empty form.
//
// Each one is an ordinary policy body, the same shape as one typed by hand and
// held to the same checks by a test, so enabling one is no different from
// having saved it yourself. Nothing is enabled until somebody presses the
// button, and what it creates is theirs to change.

// Library is the ready-made policies, in the order they are shown.
func Library() []Template {
	return libraryList
}

var libraryList = buildLibrary()

func lib(key, title, why string, scope Scope, rules, cfg map[string]any) Template {
	body := map[string]any{}
	for k, v := range rules {
		body[k] = v
	}
	if len(cfg) > 0 {
		body[ConfigKey] = cfg
	}
	b, err := json.Marshal(body)
	if err != nil {
		panic("policy: library " + key + ": " + err.Error())
	}
	return Template{Key: key, Title: title, Why: why, Scope: scope, Body: string(b)}
}

func buildLibrary() []Template {
	a := func(s string) Scope { return Scope{OSFamily: "android", Ownership: s} }
	w := Scope{OSFamily: "windows"}
	judge := func(minLen, lockSecs int) map[string]any {
		return map[string]any{"passcode_required": true, "passcode_min_length": minLen,
			"disk_encryption_required": true, "screen_lock_timeout_max": lockSecs, "jailbreak_blocked": true}
	}
	// The three tiers build on each other, so each is written as the one below
	// it plus what it adds.
	mix := func(base map[string]any, more map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range more {
			out[k] = v
		}
		return out
	}
	t1cfg := map[string]any{
		"android.password_quality": "NUMERIC", "android.password_min_length": 8,
		"android.screen_lock_seconds": 300, "android.encryption_required": true,
		"android.untrusted_apps_blocked": true, "android.debugging_blocked": true,
		"android.play_protect_required": true, "android.auto_time_required": true,
		"android.add_user_blocked": true, "android.factory_reset_blocked": true,
		"android.system_updates": "AUTOMATIC", "android.app_updates": "ALWAYS",
	}
	t1rules := map[string]any{
		"passcode_required": true, "passcode_min_length": 8, "disk_encryption_required": true,
		"screen_lock_timeout_max": 300, "jailbreak_blocked": true, "security_patch_max_age_days": 30,
		"debugging_blocked": true, "unknown_sources_blocked": true, "play_protect_required": true,
	}
	t2cfg := mix(t1cfg, map[string]any{
		"android.usb_transfer_blocked": true, "android.external_media_blocked": true,
		"android.backup_blocked": true, "android.accounts_locked": true,
		"android.tethering_blocked": true, "android.screenshots_blocked": true,
		"android.vpn_locked": true, "android.wifi_locked": true,
	})
	t2rules := mix(t1rules, map[string]any{"security_patch_max_age_days": 14, "integrity_required": true})
	t3cfg := mix(t2cfg, map[string]any{
		"android.password_quality": "ALPHANUMERIC", "android.password_min_length": 10,
		"android.password_history": 5, "android.screen_lock_seconds": 120,
		"android.play_store_mode": "WHITELIST", "android.accessibility_system_only": true,
		"android.safe_boot_blocked": true, "android.remove_user_blocked": true,
	})
	t3rules := mix(t2rules, map[string]any{
		"passcode_min_length": 10, "screen_lock_timeout_max": 120, "security_patch_max_age_days": 7,
		"on_failure": "quarantine",
	})
	return []Template{
		// ------------------------------------------------------- Android
		lib("android-baseline", "Android: secure baseline",
			"The least any Android phone should meet: an eight-character PIN, encryption, a five-minute screen lock, no apps from outside the Play Store and no debugging.",
			a(""), judge(8, 300), map[string]any{
				"android.password_quality": "NUMERIC", "android.password_min_length": 8,
				"android.screen_lock_seconds": 300, "android.encryption_required": true,
				"android.untrusted_apps_blocked": true, "android.debugging_blocked": true,
			}),
		lib("android-company-locked", "Android: company phone, locked down",
			"For phones the company owns and hands out. The person cannot reset it, change accounts, copy files off over USB, use memory cards, or change the wallpaper; updates install themselves.",
			a("company"), judge(8, 300), map[string]any{
				"android.password_quality": "NUMERIC", "android.password_min_length": 8,
				"android.screen_lock_seconds": 300, "android.encryption_required": true,
				"android.untrusted_apps_blocked": true, "android.debugging_blocked": true,
				"android.factory_reset_blocked": true, "android.safe_boot_blocked": true,
				"android.add_user_blocked": true, "android.accounts_locked": true,
				"android.usb_transfer_blocked": true, "android.external_media_blocked": true,
				"android.wallpaper_locked": true, "android.system_updates": "AUTOMATIC",
				"android.app_updates":   "ALWAYS",
				"android.short_message": "This phone is managed by your organisation.",
			}),
		lib("android-byod", "Android: personal phone with a work profile",
			"For a person's own phone. Only the work profile is managed: an eight-character PIN, and work files and text cannot be copied or shared into personal apps. Nothing here reaches personal data.",
			a("personal"), map[string]any{"passcode_required": true, "passcode_min_length": 8}, map[string]any{
				"android.password_quality": "NUMERIC", "android.password_min_length": 8,
				"android.block_copy_to_personal": true, "android.block_sharing_to_personal": true,
				"android.screenshots_blocked": true,
			}),
		lib("android-field", "Android: field agent phone",
			"For phones in the field: an eight-character PIN, only approved apps can be installed, apps update on Wi-Fi only so mobile data is not spent, and USB copying is blocked. Add the apps agents need under Apps.",
			a("company"), judge(8, 300), map[string]any{
				"android.password_quality": "NUMERIC", "android.password_min_length": 8,
				"android.screen_lock_seconds": 300, "android.encryption_required": true,
				"android.untrusted_apps_blocked": true, "android.play_store_mode": "WHITELIST",
				"android.app_updates": "WIFI_ONLY", "android.usb_transfer_blocked": true,
				"android.factory_reset_blocked": true,
			}),
		lib("android-no-capture", "Android: no camera, no screenshots",
			"For places where nothing may be photographed or captured: the camera and screenshots are blocked.",
			a(""), nil, map[string]any{"android.camera_disabled": true, "android.screenshots_blocked": true}),
		lib("android-updates", "Android: keep everything up to date",
			"System updates and app updates install themselves, so phones are not left on old versions.",
			a("company"), nil, map[string]any{"android.system_updates": "AUTOMATIC", "android.app_updates": "ALWAYS"}),

		// ----------------------------------------- the baseline's three tiers
		//
		// From the corporate baseline document, section 9. Tier 1 is the least
		// any company phone should meet, Tier 2 is for people who reach
		// sensitive systems, Tier 3 is for administrators and anybody with
		// privileged access. They are policies like any other: until devices
		// can be grouped, each applies to every company phone, so use the one
		// that fits the whole fleet and move up as groups arrive.
		lib("android-tier1", "Android: Tier 1, minimum baseline",
			"The least any company phone should meet: an eight-character PIN, encryption, a five-minute lock, no sideloading, no debugging, Play Protect on, automatic time, a patch no older than 30 days, and automatic updates.",
			a("company"), t1rules, t1cfg),
		lib("android-tier2", "Android: Tier 2, enhanced security",
			"Tier 1 plus the controls for people who reach sensitive systems: no USB copying or memory cards, no cloud backup, no added accounts, no hotspot, no screenshots, locked Wi-Fi and VPN settings, a patch within 14 days, and Google's integrity check must pass.",
			a("company"), t2rules, t2cfg),
		lib("android-tier3", "Android: Tier 3, privileged and high-risk",
			"Tier 2 plus the strictest controls, for administrators and anybody with privileged access: a longer alphanumeric password, a two-minute lock, approved apps only, only Android's own accessibility services, a patch within 7 days, and a device that fails is quarantined.",
			a("company"), t3rules, t3cfg),

		// ------------------------------------------------------- Windows
		lib("windows-baseline", "Windows: secure baseline",
			"The least any Windows computer should meet: a sign-in password of eight characters with a mix of kinds, the disk encrypted, the firewall and virus protection on, and a ten-minute screen lock.",
			w, map[string]any{"passcode_required": true, "passcode_min_length": 8, "disk_encryption_required": true,
				"firewall_required": true, "screen_lock_timeout_max": 600}, map[string]any{
				"windows.password_required": true, "windows.password_min_length": 8,
				"windows.password_complexity": 3, "windows.screen_lock_minutes": 10,
				"windows.bitlocker_required": true, "windows.firewall_on": true,
				"windows.defender_realtime": true, "windows.smartscreen": true,
			}),
		lib("windows-locked-laptop", "Windows: locked-down laptop",
			"For laptops that leave the building: the baseline, plus USB sticks cannot be written to, the device locks after ten wrong passwords, and Windows reports only what it must.",
			w, map[string]any{"passcode_required": true, "passcode_min_length": 10, "disk_encryption_required": true,
				"firewall_required": true, "screen_lock_timeout_max": 300}, map[string]any{
				"windows.password_required": true, "windows.password_min_length": 10,
				"windows.password_complexity": 3, "windows.screen_lock_minutes": 5,
				"windows.lock_after_failures": 10, "windows.bitlocker_required": true,
				"windows.firewall_on": true, "windows.defender_realtime": true,
				"windows.smartscreen": true, "windows.usb_storage_blocked": true,
				"windows.telemetry": "1",
			}),
		lib("windows-updates", "Windows: steady updates",
			"Windows installs updates itself, waits a month for big releases so problems are found by others first, and a week for monthly fixes.",
			w, nil, map[string]any{
				"windows.update_mode": "1", "windows.defer_feature_days": 30, "windows.defer_quality_days": 7,
			}),
		lib("windows-privacy", "Windows: privacy",
			"Windows sends Microsoft only what it must, location services are off, and the Cortana assistant is off.",
			w, nil, map[string]any{
				"windows.telemetry": "1", "windows.location_blocked": true, "windows.cortana_blocked": true,
			}),
	}
}

// LibraryFor lists the ready-made policies for one system.
func LibraryFor(osFamily string) []Template {
	var out []Template
	for _, t := range libraryList {
		if t.Scope.OSFamily == osFamily {
			out = append(out, t)
		}
	}
	return out
}

// LibraryByKey finds one ready-made policy.
func LibraryByKey(key string) (Template, bool) {
	for _, t := range libraryList {
		if t.Key == key {
			return t, true
		}
	}
	return Template{}, false
}
