package gateway

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"platform/internal/authz"
	"platform/internal/data"
	"platform/internal/directory"
	"platform/internal/enrol"
	"platform/internal/notify"
	"platform/internal/pki"
	"platform/internal/tenantclaim"
)

// ---------------------------------------------- trusting a device certificate
//
// This closes the gap the gateway has carried since it was written. Until
// now, a request arriving with a client certificate whose organisational
// unit was a tenant and whose common name was a device was trusted as that
// device. Nothing issued those certificates and nothing checked that we had.
//
// The check is a fingerprint lookup, not a chain verification, and that is
// deliberate. Verifying a chain proves the certificate was signed by a key
// we hold. Matching the fingerprint proves it is byte for byte a certificate
// we issued, recorded, and have not revoked, which is strictly more. It also
// means revocation is answered from the same row rather than from a list
// that has to be published and refreshed.

var (
	ErrCertUnknown  = errors.New("gateway: this device certificate was not issued here")
	ErrCertRevoked  = errors.New("gateway: this device certificate has been revoked")
	ErrCertNotValid = errors.New("gateway: this device certificate is outside its validity period")
	ErrCertMismatch = errors.New("gateway: this device certificate names a different device")
)

// deviceCertTrusted answers whether a presented certificate is one of ours.
//
// It costs one indexed query per device request. That is a real cost and it
// is listed in the README: the alternative is a cache, and a cache in front
// of a revocation check is a window during which a revoked device still
// works. The window is the whole point of revoking.
func (g *Gateway) deviceCertTrusted(ctx context.Context, host directory.Tenant,
	cert *x509.Certificate, deviceID uuid.UUID) error {

	if len(cert.Raw) == 0 {
		// A certificate with no bytes cannot be matched against anything.
		// It is not a condition that arises from a real TLS handshake.
		return ErrCertUnknown
	}
	claim, err := g.signer.Mint(tenantclaim.Claim{
		TenantID: host.ID, Subject: "device:" + deviceID.String(),
		Role: string(authz.Bootstrap), RequestID: uuid.NewString(),
	}, 30*time.Second)
	if err != nil {
		return err
	}

	return g.store.WithTenant(ctx, claim, func(ctx context.Context, tx *data.Tx) error {
		var (
			storedDevice uuid.UUID
			revokedAt    *time.Time
			notBefore    time.Time
			notAfter     time.Time
		)
		err := tx.QueryRow(ctx, `
			SELECT device_id, revoked_at, not_before, not_after
			  FROM device_certificates
			 WHERE fingerprint = $1`, pki.Fingerprint(cert.Raw)).Scan(
			&storedDevice, &revokedAt, &notBefore, &notAfter)
		if errors.Is(err, pgx.ErrNoRows) {
			// Row-level security means a certificate issued to another
			// tenant is indistinguishable here from one never issued at
			// all, which is the correct amount to know.
			return ErrCertUnknown
		}
		if err != nil {
			return err
		}
		if storedDevice != deviceID {
			// The common name and our own record disagree. It cannot happen
			// through the issuing path, because the subject is written from
			// the device id; it can happen if someone edited a row.
			return ErrCertMismatch
		}
		if revokedAt != nil {
			return ErrCertRevoked
		}
		now := time.Now().UTC()
		if now.Before(notBefore) || now.After(notAfter) {
			return ErrCertNotValid
		}
		return nil
	})
}

// ---------------------------------------------------------------- the api

type enrolmentBody struct {
	ID         uuid.UUID  `json:"id"`
	Label      string     `json:"label"`
	Ownership  string     `json:"ownership"`
	OSFamily   string     `json:"os_family"`
	State      string     `json:"state"`
	Status     string     `json:"status"`
	AssignedTo string     `json:"assigned_to,omitempty"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	DeviceID   *uuid.UUID `json:"device_id,omitempty"`
}

func toEnrolmentBody(e enrol.Enrolment, now time.Time) enrolmentBody {
	return enrolmentBody{
		ID: e.ID, Label: e.Label, Ownership: e.Ownership, OSFamily: e.OSFamily,
		State: e.State, Status: e.Status(now), AssignedTo: e.AssignedTo,
		CreatedBy: e.CreatedBy,
		CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt, DeviceID: e.DeviceID,
	}
}

func enrolStatusFor(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, enrol.ErrNoSuchToken), errors.Is(err, enrol.ErrNotPending),
		errors.Is(err, enrol.ErrExpired):
		// One answer for every way a token can be no good. Telling them
		// apart hands a guesser a way to learn which of their guesses was
		// once real.
		return http.StatusForbidden, "this enrolment link is not valid"
	case errors.Is(err, pki.ErrBadCSR), errors.Is(err, pki.ErrCSRSignature),
		errors.Is(err, pki.ErrWeakKey), errors.Is(err, enrol.ErrNoCSR),
		errors.Is(err, enrol.ErrDeviceSerial):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, enrol.ErrBadInput), errors.Is(err, enrol.ErrLifeTooLong):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, enrol.ErrDeviceCap), strings.Contains(err.Error(), "device cap reached"):
		return http.StatusConflict, strings.TrimPrefix(err.Error(), "enrol: ")
	default:
		return http.StatusInternalServerError, "the enrolment could not be completed"
	}
}

type createEnrolmentInput struct {
	Label     string `json:"label"`
	Ownership string `json:"ownership"`
	OSFamily  string `json:"os_family"`
	Days      int    `json:"days"`
	// AssignedTo is whose device this will be. It is the only moment the
	// link can be made: by the time a machine is reporting, nothing on it
	// says whose desk it is on.
	AssignedTo string `json:"assigned_to"`
}

func readEnrolmentInput(r *http.Request) createEnrolmentInput {
	var in createEnrolmentInput
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(ct, "multipart/form-data") {
		_ = r.ParseForm()
		in.Label = r.FormValue("label")
		in.Ownership = r.FormValue("ownership")
		in.OSFamily = r.FormValue("os_family")
		in.AssignedTo = r.FormValue("assigned_to")
		if n, err := strconv.Atoi(r.FormValue("days")); err == nil {
			in.Days = n
		}
		return in
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	return in
}

func (g *Gateway) createEnrolment(w http.ResponseWriter, r *http.Request) {
	if g.enrol == nil {
		writeError(w, http.StatusNotImplemented, "enrolment is not configured")
		return
	}
	in := readEnrolmentInput(r)

	var (
		e     enrol.Enrolment
		token string
	)
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var cerr error
			e, token, cerr = g.enrol.Create(ctx, tx, enrol.CreateInput{
				Label: in.Label, Ownership: in.Ownership, OSFamily: in.OSFamily,
				AssignedTo: in.AssignedTo,
				Life:       time.Duration(in.Days) * 24 * time.Hour,
			})
			return cerr
		})
	if err != nil {
		status, msg := enrolStatusFor(err)
		writeError(w, status, msg)
		return
	}

	res := ResolutionFrom(r.Context())
	g.log.Info("enrolment created", "tenant", res.Tenant.Slug,
		"enrolment", e.ID, "by", res.Subject)

	// The token is in this response and in no other. It is not logged, not
	// stored, and not retrievable afterwards.
	writeJSON(w, http.StatusCreated, map[string]any{
		"enrolment": toEnrolmentBody(e, time.Now().UTC()),
		"token":     token,
		"url":       g.enrolURL(r, token),
	})
}

func (g *Gateway) enrolURL(r *http.Request, token string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/enrol?t=" + token
}

func (g *Gateway) listEnrolments(w http.ResponseWriter, r *http.Request) {
	var out []enrolmentBody
	now := time.Now().UTC()
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			es, err := enrol.List(ctx, tx, 100)
			if err != nil {
				return err
			}
			out = make([]enrolmentBody, 0, len(es))
			for _, e := range es {
				out = append(out, toEnrolmentBody(e, now))
			}
			return nil
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list enrolments")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrolments": out})
}

func (g *Gateway) revokeEnrolment(w http.ResponseWriter, r *http.Request) {
	if g.enrol == nil {
		writeError(w, http.StatusNotImplemented, "enrolment is not configured")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such enrolment")
		return
	}
	reason := readInput(r).Reason
	if reason == "" {
		reason = "withdrawn by an administrator"
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return g.enrol.Revoke(ctx, tx, id, reason)
		})
	if errors.Is(err, enrol.ErrNotPending) {
		writeError(w, http.StatusConflict,
			"that enrolment has already been used or withdrawn")
		return
	}
	if err != nil {
		status, msg := enrolStatusFor(err)
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}

// ------------------------------------------------------------ redeeming
//
// This route sits outside entry with the sign-in routes, because the thing
// calling it is a device that has no session and no certificate yet. Its
// credential is the token in the body. That makes it the fourth and last
// entry in the platform's unauthenticated surface.

type redeemInput struct {
	Token  string `json:"token"`
	CSR    string `json:"csr"`    // PEM or base64 DER
	Serial string `json:"serial"` // the hardware serial the device reports
	Name   string `json:"name"`
}

// decodeCSR takes what a device actually sends. OpenSSL produces PEM, most
// agent libraries produce DER, and base64 of DER is what survives JSON.
// Accepting all three costs ten lines and removes a whole class of
// first-enrolment support call.
func decodeCSR(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, enrol.ErrNoCSR
	}
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil || !strings.Contains(block.Type, "CERTIFICATE REQUEST") {
			return nil, pki.ErrBadCSR
		}
		return block.Bytes, nil
	}
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		der, err = base64.RawURLEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, pki.ErrBadCSR
	}
	return der, nil
}

func (g *Gateway) redeemEnrolment(w http.ResponseWriter, r *http.Request) {
	host, ok := g.publicHost(w, r)
	if !ok {
		return
	}
	if g.enrol == nil {
		writeError(w, http.StatusNotImplemented, "enrolment is not configured")
		return
	}

	var in redeemInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "the enrolment request could not be read")
		return
	}
	csr, err := decodeCSR(in.CSR)
	if err != nil {
		status, msg := enrolStatusFor(err)
		writeError(w, status, msg)
		return
	}

	// The claim is minted for the tenant the HOSTNAME named, never for one
	// named in the body. A token is a credential, not a routing instruction:
	// a Kalesi token presented to Arbor's hostname finds nothing, because
	// the lookup happens inside Arbor's row-level security.
	claim, err := g.signer.Mint(tenantclaim.Claim{
		TenantID: host.ID, Subject: "enrolling-device",
		Role: string(authz.Bootstrap), RequestID: uuid.NewString(),
	}, time.Minute)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start the enrolment")
		return
	}

	var out enrol.Redeemed
	err = g.store.WithTenant(r.Context(), claim, func(ctx context.Context, tx *data.Tx) error {
		var rerr error
		out, rerr = g.enrol.Redeem(ctx, tx, enrol.RedeemInput{
			Token: in.Token, CSR: csr, Serial: in.Serial, Name: in.Name,
		})
		return rerr
	})
	if err != nil {
		status, msg := enrolStatusFor(err)
		g.log.Warn("enrolment refused", "tenant", host.Slug, "status", status,
			"reason", msg, "err", err)
		writeError(w, status, msg)
		return
	}

	g.log.Info("device enrolled", "tenant", host.Slug, "device", out.Device.ID,
		"reenrolled", out.Reenrolled)
	writeJSON(w, http.StatusCreated, map[string]any{
		"device_id":   out.Device.ID,
		"name":        out.Device.Name,
		"certificate": string(out.Certificate),
		"authority":   string(out.Authority),
		"not_after":   out.NotAfter,
		"reenrolled":  out.Reenrolled,
	})
}

// ------------------------------------------------------------- renewal

// renewCertificate is a device asking for a fresh certificate using the one
// it already holds.
//
// It is on the device's own route list, beside reporting and acknowledging,
// and it is reachable only on the device certificate path. The fingerprint
// comes from the TLS connection rather than from the body: a fingerprint in
// a body is a claim, and what makes this safe is that the device is
// authenticated by what it holds.
//
// Everything that makes a revoked or expired certificate unable to renew has
// already happened by the time this runs. g.deviceCertTrusted refused it
// during resolution, before any route was chosen. That ordering is the
// design: a renewal path with its own authentication would be a way around
// revocation, and revocation would then be decorative.
func (g *Gateway) renewCertificate(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	if res.Source != "device_certificate" {
		writeError(w, http.StatusForbidden, "only a device may renew its own certificate")
		return
	}
	if g.enrol == nil {
		writeError(w, http.StatusNotImplemented, "enrolment is not configured")
		return
	}

	var in struct {
		CSR string `json:"csr"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "the renewal request could not be read")
		return
	}
	csr, err := decodeCSR(in.CSR)
	if err != nil {
		status, msg := enrolStatusFor(err)
		writeError(w, status, msg)
		return
	}

	// From the connection, never the body.
	presented := pki.Fingerprint(r.TLS.PeerCertificates[0].Raw)

	var out enrol.Renewed
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var rerr error
			out, rerr = g.enrol.Renew(ctx, tx, res.DeviceID, presented, csr)
			return rerr
		})
	switch {
	case errors.Is(err, enrol.ErrNotDueForRenewal):
		// Not a failure. A device asking early is a device working
		// correctly on a clock that is slightly off, and it should be told
		// when to come back rather than treated as broken.
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": err.Error(), "renew_within_days": int(enrol.RenewalWindow.Hours() / 24),
		})
		return
	case errors.Is(err, enrol.ErrUnknownCertificate):
		writeError(w, http.StatusForbidden, "that certificate cannot be renewed")
		return
	case err != nil:
		status, msg := enrolStatusFor(err)
		g.log.Warn("renewal refused", "tenant", res.Tenant.Slug,
			"device", res.DeviceID, "status", status, "err", err)
		writeError(w, status, msg)
		return
	}

	g.log.Info("certificate renewed", "tenant", res.Tenant.Slug,
		"device", res.DeviceID, "until", out.NotAfter.Format(time.RFC3339))
	writeJSON(w, http.StatusCreated, map[string]any{
		"certificate": string(out.Certificate),
		"authority":   string(out.Authority),
		"not_after":   out.NotAfter,
	})
}

// SweepExpiring tells somebody about devices whose certificate is running
// out and which have not renewed.
//
// It is called on a timer beside the notification worker. A device that is
// off, or whose agent has stopped, quietly stops being able to authenticate
// on the day its certificate expires, and until this existed the first
// anyone knew was a device going silent, which looks exactly like a stolen
// laptop and gets investigated as one.
func (g *Gateway) SweepExpiring(ctx context.Context, tx *data.Tx) (int, error) {
	now := time.Now().UTC()
	due, err := enrol.Expiring(ctx, tx, enrol.ExpiringSoon, now)
	if err != nil {
		return 0, err
	}
	for _, d := range due {
		days := int(d.NotAfter.Sub(now).Hours() / 24)
		when := fmt.Sprintf("in %d days", days)
		if days <= 0 {
			when = "already"
		}
		if err := g.tell(ctx, tx, notify.Message{
			Topic:   notify.CertificateExpiring,
			Subject: d.Name + " will stop reporting " + when,
			Body: "Its identity certificate expires on " +
				d.NotAfter.Format("2 January 2006") + " and it has not renewed. " +
				"A device renews by itself in the last " +
				fmt.Sprint(int(enrol.RenewalWindow.Hours()/24)) +
				" days, so one that has not is either switched off or its agent " +
				"has stopped. After it expires the device must be enrolled again.",
			ObjectRef: "device:" + d.DeviceID.String(),
			// One message per device per expiry, not one per sweep. The
			// sweep runs daily and would otherwise say the same thing
			// about the same device every day for six weeks, which is how
			// a channel gets muted.
			Once: true,
			DedupeKey: "cert-expiring:" + d.DeviceID.String() + ":" +
				d.NotAfter.Format("2006-01-02"),
		}); err != nil {
			return 0, err
		}
	}
	return len(due), nil
}

// RunExpirySweep walks tenants on a timer and warns about certificates
// running out.
//
// It is a method on the gateway rather than a package of its own because it
// needs the notifier, the store and the signer, which the gateway already
// holds. Daily, because the window it warns inside is measured in weeks and
// a sweep every minute would be a notification system testing its own
// deduplication.
func (g *Gateway) RunExpirySweep(ctx context.Context, tenants func(context.Context) ([]uuid.UUID, error), every time.Duration) {
	if every <= 0 {
		every = 24 * time.Hour
	}
	g.log.Info("certificate expiry sweep running", "every", every)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
		ids, err := tenants(ctx)
		if err != nil {
			g.log.Error("expiry sweep: could not list tenants", "err", err)
			continue
		}
		for _, id := range ids {
			claim, err := g.signer.Mint(tenantclaim.Claim{
				TenantID: id, Subject: "system:expiry-sweep",
				Role: string(authz.Operator), RequestID: uuid.NewString(),
			}, 2*time.Minute)
			if err != nil {
				continue
			}
			if err := g.store.WithTenant(ctx, claim,
				func(ctx context.Context, tx *data.Tx) error {
					n, serr := g.SweepExpiring(ctx, tx)
					if serr == nil && n > 0 {
						g.log.Info("certificates running out", "tenant", id, "devices", n)
					}
					return serr
				}); err != nil {
				g.log.Error("expiry sweep", "tenant", id, "err", err)
			}
		}
	}
}
