package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"platform/internal/console"
	"platform/internal/data"
	"platform/internal/notify"
)

type targetBody struct {
	Topic    string `json:"topic"`
	Means    string `json:"means"`
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint"`
}

type setTargetInput struct {
	Topic    string `json:"topic"`
	Kind     string `json:"kind"`
	Endpoint string `json:"endpoint"`
}

func notifyStatusFor(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, notify.ErrBadTopic), errors.Is(err, notify.ErrBadEndpoint):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, notify.ErrNoTarget):
		return http.StatusNotFound, "nothing was listening for that"
	default:
		return http.StatusInternalServerError, "that could not be saved"
	}
}

func (g *Gateway) listNotifications(w http.ResponseWriter, r *http.Request) {
	if g.notify == nil {
		writeError(w, http.StatusNotImplemented, "notifications are not configured")
		return
	}
	var (
		targets []targetBody
		recent  []notify.Record
	)
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			ts, err := g.notify.Targets(ctx, tx)
			if err != nil {
				return err
			}
			targets = make([]targetBody, 0, len(ts))
			for _, t := range ts {
				targets = append(targets, targetBody{
					Topic: string(t.Topic), Means: t.Topic.Describe(),
					Kind: t.Kind,
					// Redacted, never the endpoint. A chat webhook URL is a
					// credential, and a settings page that prints it back
					// hands it to anyone who can read the page.
					Endpoint: t.Redacted(),
				})
			}
			recent, err = notify.Recent(ctx, tx, 50)
			return err
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the notification settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"targets": targets, "recent": recent, "topics": notify.Topics(),
	})
}

func (g *Gateway) setNotificationTarget(w http.ResponseWriter, r *http.Request) {
	if g.notify == nil {
		writeError(w, http.StatusNotImplemented, "notifications are not configured")
		return
	}
	res := ResolutionFrom(r.Context())

	var in setTargetInput
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		_ = r.ParseForm()
		in = setTargetInput{Topic: r.FormValue("topic"), Kind: r.FormValue("kind"),
			Endpoint: r.FormValue("endpoint")}
	} else if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).
		Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "that could not be read")
		return
	}

	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return g.notify.SetTarget(ctx, tx, notify.Topic(in.Topic),
				in.Kind, in.Endpoint, res.Subject)
		})
	if err != nil {
		status, msg := notifyStatusFor(err)
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"topic": in.Topic, "kind": in.Kind})
}

// ---------------------------------------------------------------- console

func (g *Gateway) consoleSetTarget(w http.ResponseWriter, r *http.Request, res Resolution) {
	if g.notify == nil {
		back(w, r, "/notifications", "Notifications are not configured on this deployment.")
		return
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return g.notify.SetTarget(ctx, tx, notify.Topic(r.FormValue("topic")),
				r.FormValue("kind"), r.FormValue("endpoint"), res.Subject)
		})
	if err != nil {
		_, msg := notifyStatusFor(err)
		back(w, r, "/notifications", "That was not saved. "+msg)
		return
	}
	back(w, r, "/notifications", "Saved. The next one goes there.")
}

func (g *Gateway) consoleClearTarget(w http.ResponseWriter, r *http.Request, res Resolution) {
	if g.notify == nil {
		back(w, r, "/notifications", "Notifications are not configured on this deployment.")
		return
	}
	topic := notify.Topic(r.PathValue("topic"))
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return g.notify.ClearTarget(ctx, tx, topic)
		})
	if err != nil {
		back(w, r, "/notifications", "Nothing was listening for that.")
		return
	}
	back(w, r, "/notifications",
		"Cleared. Nothing will be told about that until somewhere else is named.")
}

// notificationsPage is the console's read, assembled here because the
// console package has no business holding a notify.Service.
func (g *Gateway) notificationsPage(ctx context.Context, tx *data.Tx,
	p *console.Notifications) error {

	ts, err := g.notify.Targets(ctx, tx)
	if err != nil {
		return err
	}
	for _, t := range ts {
		p.Targets = append(p.Targets, console.NotificationTarget{
			Topic: string(t.Topic), Means: t.Topic.Describe(),
			Kind: t.Kind, Endpoint: t.Redacted(), CreatedBy: t.CreatedBy,
		})
	}
	for _, topic := range notify.Topics() {
		p.Topics = append(p.Topics, console.NotificationTopic{
			Topic: string(topic), Means: topic.Describe(),
			Configured: hasTarget(ts, topic),
		})
	}
	domains, err := g.notify.Domains(ctx, tx)
	if err != nil {
		return err
	}
	for _, d := range domains {
		p.Domains = append(p.Domains, console.SendingDomain{
			Domain: d.Domain, From: d.From(), Verified: d.Verified,
			RecordName: d.RecordName(), RecordValue: d.RecordValueSplit(),
			LastError: d.LastError,
		})
	}
	p.WhyNoSPF = notify.WhyNoSPFRecord

	recent, err := notify.Recent(ctx, tx, 30)
	if err != nil {
		return err
	}
	for _, r := range recent {
		p.Recent = append(p.Recent, console.NotificationRecord{
			Topic: r.Topic, Subject: r.Subject, State: r.State,
			Attempts: r.Attempts, LastError: r.LastError,
			CreatedAt: r.CreatedAt, Delivered: r.Delivered(),
		})
	}
	return nil
}

func hasTarget(ts []notify.Target, topic notify.Topic) bool {
	for _, t := range ts {
		if t.Topic == topic {
			return true
		}
	}
	return false
}

// consoleNotifications hands the page its loader.
func (g *Gateway) consoleNotifications(w http.ResponseWriter, r *http.Request, s console.Session) {
	if g.notify == nil {
		http.Error(w, "Notifications are not configured on this deployment.",
			http.StatusNotImplemented)
		return
	}
	g.console.NotificationsPage(w, r, s, g.notificationsPage)
}

var _ = time.Now

// ------------------------------------------------- sending domains

type sendingDomainBody struct {
	Domain      string   `json:"domain"`
	From        string   `json:"from"`
	Verified    bool     `json:"verified"`
	RecordName  string   `json:"record_name"`
	RecordValue []string `json:"record_value"`
	LastError   string   `json:"last_error,omitempty"`
}

func toSendingDomainBody(d notify.SendingDomain) sendingDomainBody {
	return sendingDomainBody{
		Domain: d.Domain, From: d.From(), Verified: d.Verified,
		RecordName: d.RecordName(), RecordValue: d.RecordValueSplit(),
		LastError: d.LastError,
	}
}

func (g *Gateway) listSendingDomains(w http.ResponseWriter, r *http.Request) {
	if g.notify == nil {
		writeError(w, http.StatusNotImplemented, "notifications are not configured")
		return
	}
	var out []sendingDomainBody
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			ds, err := g.notify.Domains(ctx, tx)
			if err != nil {
				return err
			}
			out = make([]sendingDomainBody, 0, len(ds))
			for _, d := range ds {
				out = append(out, toSendingDomainBody(d))
			}
			return nil
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the sending domains")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"domains": out, "why_no_spf": notify.WhyNoSPFRecord,
	})
}

func (g *Gateway) registerSendingDomain(w http.ResponseWriter, r *http.Request) {
	if g.notify == nil {
		writeError(w, http.StatusNotImplemented, "notifications are not configured")
		return
	}
	res := ResolutionFrom(r.Context())
	var in struct {
		Domain string `json:"domain"`
		Local  string `json:"from_local"`
	}
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		_ = r.ParseForm()
		in.Domain = r.FormValue("domain")
		in.Local = r.FormValue("from_local")
	} else if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).
		Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "that could not be read")
		return
	}

	var d notify.SendingDomain
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var rerr error
			d, rerr = g.notify.Register(ctx, tx, in.Domain, res.Subject)
			if rerr != nil {
				return rerr
			}
			if in.Local != "" {
				return g.notify.SetFromLocal(ctx, tx, d.Domain, in.Local)
			}
			return nil
		})
	if err != nil {
		status, msg := sendingStatusFor(err)
		g.log.Error("sending domain", "domain", in.Domain, "status", status, "err", err)
		writeError(w, status, msg)
		return
	}
	g.log.Info("sending domain registered", "tenant", res.Tenant.Slug,
		"domain", d.Domain, "by", res.Subject)
	writeJSON(w, http.StatusCreated, toSendingDomainBody(d))
}

// verifySendingDomain is the proof. Nothing signs as a domain until this has
// found our own public key published in that domain's DNS.
func (g *Gateway) verifySendingDomain(w http.ResponseWriter, r *http.Request) {
	if g.notify == nil {
		writeError(w, http.StatusNotImplemented, "notifications are not configured")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))

	var (
		d       notify.SendingDomain
		failure error
	)
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var verr error
			d, verr = g.notify.Verify(ctx, tx, domain)
			if errors.Is(verr, notify.ErrNoSendingDomain) {
				return verr
			}
			// A failed check is RECORDED: the row now carries why, and
			// returning the error here would roll that away. Same shape as
			// the limiter's refusal.
			failure = verr
			return nil
		})
	if err != nil {
		status, msg := sendingStatusFor(err)
		writeError(w, status, msg)
		return
	}
	if failure != nil {
		writeJSON(w, http.StatusConflict, map[string]any{
			"verified": false, "error": failure.Error(),
			"domain": toSendingDomainBody(d),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"verified": true, "domain": toSendingDomainBody(d),
	})
}

func (g *Gateway) removeSendingDomain(w http.ResponseWriter, r *http.Request) {
	if g.notify == nil {
		writeError(w, http.StatusNotImplemented, "notifications are not configured")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return g.notify.RemoveDomain(ctx, tx, domain)
		})
	if err != nil {
		status, msg := sendingStatusFor(err)
		writeError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": domain})
}

func sendingStatusFor(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, notify.ErrBadDomain):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, notify.ErrNoSendingDomain):
		return http.StatusNotFound, "no such sending domain"
	case errors.Is(err, notify.ErrBadEndpoint):
		return http.StatusBadRequest, err.Error()
	default:
		return http.StatusInternalServerError, "that could not be saved"
	}
}

// ---------------------------------------------------------------- console

func (g *Gateway) consoleRegisterDomain(w http.ResponseWriter, r *http.Request, res Resolution) {
	if g.notify == nil {
		back(w, r, "/notifications", "Notifications are not configured.")
		return
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			d, rerr := g.notify.Register(ctx, tx, r.FormValue("domain"), res.Subject)
			if rerr != nil {
				return rerr
			}
			if local := r.FormValue("from_local"); local != "" {
				return g.notify.SetFromLocal(ctx, tx, d.Domain, local)
			}
			return nil
		})
	if err != nil {
		_, msg := sendingStatusFor(err)
		back(w, r, "/notifications", "That domain was not added. "+msg)
		return
	}
	back(w, r, "/notifications",
		"Added. Publish the record below, then press Check, and mail will go out as your domain.")
}

func (g *Gateway) consoleVerifyDomain(w http.ResponseWriter, r *http.Request, res Resolution) {
	if g.notify == nil {
		back(w, r, "/notifications", "Notifications are not configured.")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	var failure error
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			_, verr := g.notify.Verify(ctx, tx, domain)
			if errors.Is(verr, notify.ErrNoSendingDomain) {
				return verr
			}
			failure = verr
			return nil
		})
	switch {
	case err != nil:
		back(w, r, "/notifications", "No such domain.")
	case failure != nil:
		// The reason, not a generic failure: DNS takes time to propagate
		// and "it did not work" sends somebody to open a ticket.
		back(w, r, "/notifications", "Not yet. "+failure.Error())
	default:
		back(w, r, "/notifications",
			"Verified. Your notifications will now be sent as your own domain and signed.")
	}
}

func (g *Gateway) consoleRemoveDomain(w http.ResponseWriter, r *http.Request, res Resolution) {
	if g.notify == nil {
		back(w, r, "/notifications", "Notifications are not configured.")
		return
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return g.notify.RemoveDomain(ctx, tx,
				strings.ToLower(strings.TrimSpace(r.PathValue("domain"))))
		})
	if err != nil {
		back(w, r, "/notifications", "No such domain.")
		return
	}
	back(w, r, "/notifications",
		"Removed. Mail goes back to being sent from this console's own address.")
}
