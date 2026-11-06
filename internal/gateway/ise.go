package gateway

import (
	"context"
	"encoding/xml"
	"net/http"
	"strings"
	"time"

	"platform/internal/branding"
	"platform/internal/data"
	"platform/internal/policy"
)

// The access feed in the shape Cisco ISE asks for it: its MDM API,
// version 2. ISE is configured with this platform's hostname and an
// integration token as the password of an HTTP Basic credential; it calls
// mdminfo once to learn the API, then mdmapi with the MAC address of each
// device that authenticates, and reads the compliance answer out of the
// XML. The answer is the feed's answer, worded for ISE: compliant means
// the door says allow, and the failure reason is the door's reason.
//
// Built to Cisco's published shape for the API and held to it by the
// tests here; it has not yet been run against an ISE. The product named
// in mdminfo is the tenant's own brand, never the operator's.

type iseInfo struct {
	XMLName        xml.Name `xml:"ise_api"`
	Name           string   `xml:"name"`
	APIVersion     int      `xml:"api_version"`
	APIPath        string   `xml:"api_path"`
	RedirectURL    string   `xml:"redirect_url"`
	MDMVendor      string   `xml:"mdm_vendor"`
	ProductName    string   `xml:"product_name"`
	ProductVersion string   `xml:"product_version"`
}

type iseAnswer struct {
	XMLName    xml.Name    `xml:"ise_api"`
	Name       string      `xml:"name"`
	APIVersion int         `xml:"api_version"`
	Devices    []iseDevice `xml:"deviceList>device"`
}

type iseDevice struct {
	MACAddress string        `xml:"macaddress"`
	Attributes iseAttributes `xml:"attributes"`
}

type iseAttributes struct {
	RegisterStatus bool          `xml:"register_status"`
	Compliance     iseCompliance `xml:"compliance"`
	// The booleans the device may not have reported are pointers: an
	// element that is absent says "unknown", which ISE treats as such,
	// where "false" would say something the device did not.
	DiskEncryptionOn *bool  `xml:"disk_encryption_on,omitempty"`
	PinLockOn        *bool  `xml:"pin_lock_on,omitempty"`
	JailBroken       *bool  `xml:"jail_broken,omitempty"`
	UDID             string `xml:"udid,omitempty"`
	SerialNumber     string `xml:"serial_number,omitempty"`
	OSVersion        string `xml:"os_version,omitempty"`
	Model            string `xml:"model,omitempty"`
}

type iseCompliance struct {
	Status        bool   `xml:"status"`
	FailureReason string `xml:"failure_reason,omitempty"`
	Remediation   string `xml:"remediation,omitempty"`
}

const iseAPIVersion = 2

func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(v)
}

func (g *Gateway) iseInfo(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	product := res.Tenant.Name
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			b, berr := branding.Load(ctx, tx)
			if berr != nil {
				return berr
			}
			if !b.IsPlaceholder() {
				product = b.ProductName
			}
			return nil
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the brand")
		return
	}
	writeXML(w, http.StatusOK, iseInfo{
		Name: "mdminfo", APIVersion: iseAPIVersion, APIPath: "/ciscoise/mdmapi",
		RedirectURL: "https://" + r.Host + "/me",
		MDMVendor:   product, ProductName: product, ProductVersion: "1",
	})
}

// iseQuery answers one MAC. ISE asks querycriteria=macaddress&value=...;
// the other criteria it has (all, with paging) are not answered, said
// plainly rather than answered with an empty list ISE would read as "no
// devices are registered".
func (g *Gateway) iseQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if v := q.Get("ise_api_version"); v != "" && v != "2" {
		writeError(w, http.StatusBadRequest, "this platform answers MDM API version 2")
		return
	}
	if strings.ToLower(q.Get("querycriteria")) != "macaddress" {
		writeError(w, http.StatusBadRequest, "ask by macaddress; a full-fleet query is answered by /api/network/denied")
		return
	}
	mac, ok := data.NormaliseMAC(q.Get("value"))
	if !ok {
		writeError(w, http.StatusBadRequest, "that is not a MAC address")
		return
	}

	dev := iseDevice{MACAddress: mac}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			id, has, derr := data.DeviceByMAC(ctx, tx, mac)
			if derr != nil || !has {
				return derr
			}
			v, found, aerr := data.NetworkAccessByID(ctx, tx, id, policy.MaxReportAge)
			if aerr != nil || !found {
				return aerr
			}
			d, gerr := data.GetDevice(ctx, tx, id)
			if gerr != nil {
				return gerr
			}
			a := iseAttributes{
				RegisterStatus: true,
				Compliance:     iseCompliance{Status: v.Access == "allow", FailureReason: v.Reason},
				UDID:           id.String(), SerialNumber: d.Serial, Model: d.OSFamily,
			}
			if c, ok, cerr := policy.Of(ctx, tx, id, time.Now().UTC()); cerr != nil {
				return cerr
			} else if ok {
				a.DiskEncryptionOn = c.Report.DiskEncryption
				a.PinLockOn = c.Report.PasscodeSet
				a.JailBroken = c.Report.Jailbroken
				a.OSVersion = c.Report.OSVersion
				if a.Compliance.FailureReason == "" && len(c.Findings) > 0 && v.Access != "allow" {
					a.Compliance.FailureReason = c.Findings[0].Rule
				}
				if !a.Compliance.Status && len(c.Findings) > 0 {
					a.Compliance.Remediation = c.Findings[0].Rule + " (" + c.Findings[0].Saw + ")"
				}
			}
			dev.Attributes = a
			return nil
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the device")
		return
	}
	// A MAC no device has reported: present in the list, registered
	// false, compliant false. ISE reads that as "not enrolled here" and
	// its own policy for unmanaged devices applies.
	writeXML(w, http.StatusOK, iseAnswer{Name: "attributes", APIVersion: iseAPIVersion, Devices: []iseDevice{dev}})
}
