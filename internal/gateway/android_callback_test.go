package gateway

import (
	"net/http/httptest"
	"testing"
)

// Google sends the administrator back only to an https address. A console
// on a laptop is plain http, so it names a separate https listener as the
// place to come back to; a deployed console, which is https already, needs
// nothing and uses its own address.
func TestTheAndroidCallbackGoesWhereGoogleCanSendIt(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost:8090/android/bind", nil)
	r.Host = "localhost:8090"

	laptop := &Gateway{insecureCookies: true, androidCallback: "https://localhost:8092/"}
	if got := laptop.androidCallbackURL(r); got != "https://localhost:8092/android/callback" {
		t.Fatalf("laptop callback is %q", got)
	}

	plain := &Gateway{insecureCookies: true}
	if got := plain.androidCallbackURL(r); got != "http://localhost:8090/android/callback" {
		t.Fatalf("without a base the console's own address is used: %q", got)
	}

	deployed := &Gateway{}
	r.Host = "mdm.kalesi.example"
	if got := deployed.androidCallbackURL(r); got != "https://mdm.kalesi.example/android/callback" {
		t.Fatalf("deployed callback is %q", got)
	}
}
