package qr

import (
	"strings"
	"testing"

	"platform/internal/qr/qrtest"
)

// What is drawn is what a decoder that shares no code with the encoder
// reads back. A test that only checked the encoder against itself would pass
// for a code nobody can scan.
func TestWhatIsDrawnIsWhatIsScanned(t *testing.T) {
	link := "https://enterprise.google.com/android/enroll?et=ABCDEF123456"
	// The size and shape of what Google returns for a company phone.
	provisioning := `{"android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME":` +
		`"com.google.android.apps.work.clouddpc/.receivers.CloudDeviceAdminReceiver",` +
		`"android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM":"I5YvS0O5hXY46mb01BlRjq4oJJGs2kuUcHvVkAPEXlg",` +
		`"android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION":` +
		`"https://play.google.com/managed/downloadManagingApp?identifier=setup",` +
		`"android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE":{` +
		`"com.google.android.apps.work.clouddpc.EXTRA_ENROLLMENT_TOKEN":"QWERTY123456789ZXCV"}}`
	for name, text := range map[string]string{"link": link, "provisioning payload": provisioning} {
		u, err := DataURL(text)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := qrtest.ScanDataURL(t, string(u)); got != text {
			t.Errorf("%s: scanned %q, drew %q", name, got, text)
		}
	}
}

func TestNothingToDrawIsAnError(t *testing.T) {
	if _, err := DataURL(""); err != ErrEmpty {
		t.Fatalf("empty text gave %v", err)
	}
	if _, err := PNG(strings.Repeat("x", 4000)); err == nil {
		t.Fatal("a payload too large for any QR code was drawn")
	}
}
