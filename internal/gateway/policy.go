package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"platform/internal/catalog"
	"platform/internal/data"
	"platform/internal/policy"
)

// ------------------------------------------------------------- reporting
//
// A device reports on itself and on nothing else. The rule is the same one
// the command acknowledgement already follows: this route is reachable only
// on the device certificate path, and only for the device that certificate
// names.
//
// The alternative — letting an administrator post a report on a device's
// behalf — would make every compliance verdict deniable. A fleet is only
// evidence if the evidence comes from the machines.

func (g *Gateway) reportDevice(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	if res.Source != "device_certificate" {
		writeError(w, http.StatusForbidden, "only a device may report on itself")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	if id != res.DeviceID {
		// A managed device trying to report on another one. 404 rather than
		// 403, for the same reason everywhere else: a forbidden answer
		// confirms the device exists.
		writeError(w, http.StatusNotFound, "no such device")
		return
	}

	var rep policy.Report
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&rep); err != nil {
		writeError(w, http.StatusBadRequest, "the report could not be read")
		return
	}

	var out policy.Compliance
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var aerr error
			out, aerr = policy.Apply(ctx, tx, id, rep, time.Now().UTC())
			return aerr
		})
	if errors.Is(err, policy.ErrNoDevice) {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	if err != nil {
		g.log.Error("evaluate", "device", id, "err", err)
		writeError(w, http.StatusInternalServerError, "the report could not be evaluated")
		return
	}

	g.log.Info("device reported", "tenant", res.Tenant.Slug, "device", id,
		"state", out.State, "findings", len(out.Findings), "enforcement", out.Enforcement)
	// The device is told its own verdict and why, so an agent can show the
	// person holding the laptop what to fix without them opening a console
	// they may not have an account for.
	writeJSON(w, http.StatusOK, complianceBody(out))
}

func complianceBody(c policy.Compliance) map[string]any {
	body := map[string]any{
		"state":        c.State,
		"reported_at":  c.ReportedAt,
		"evaluated_at": c.EvaluatedAt,
		"findings":     c.Findings,
		"policies":     c.Policies,
	}
	// The device's own state travels with the verdict, so an agent knows
	// it has been quarantined and can tell the person, or act locally.
	if c.DeviceState != "" {
		body["device_state"] = c.DeviceState
	}
	if c.Enforcement != "" {
		body["enforcement"] = c.Enforcement
	}
	return body
}

// releaseDevice is a person letting a quarantined device back in. Same
// roles as the emergency lock: the people who may act on a device in a
// hurry are the people who may say the hurry is over.
func (g *Gateway) releaseDevice(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return policy.Release(ctx, tx, id, res.Subject)
		})
	if errors.Is(err, data.ErrNotQuarantined) {
		writeError(w, http.StatusConflict, "that device is not quarantined")
		return
	}
	if err != nil {
		g.log.Error("release", "device", id, "err", err)
		writeError(w, http.StatusInternalServerError, "the device could not be released")
		return
	}
	g.log.Info("device released", "tenant", res.Tenant.Slug, "device", id, "by", res.Subject)
	writeJSON(w, http.StatusOK, map[string]any{"state": "state_unknown"})
}

// getCompliance is the console's and the API's read of the same verdict.
func (g *Gateway) getCompliance(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	var (
		c     policy.Compliance
		found bool
	)
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var gerr error
			c, found, gerr = policy.Of(ctx, tx, id, time.Now().UTC())
			return gerr
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the verdict")
		return
	}
	if !found {
		// Not an error. A device that has never reported has no verdict,
		// and saying so is more useful than inventing one.
		writeJSON(w, http.StatusOK, map[string]any{
			"state": "awaiting_first_boot", "findings": []any{}, "policies": []any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, complianceBody(c))
}

// ---------------------------------------------------------------- policies

type policyBody struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Version   int       `json:"version"`
	Active    bool      `json:"active"`
	AppliesTo string    `json:"applies_to"`
	Requires  []string  `json:"requires"`
	Stage     string    `json:"stage,omitempty"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	// AndroidJudgedOnly names the rules Android devices are judged on at
	// sync rather than held to by Google. Only present when a tenant has
	// an Android Enterprise and the policy was delivered to it.
	AndroidJudgedOnly []string `json:"android_judged_only,omitempty"`
}

func toPolicyBody(p policy.Policy) policyBody {
	return policyBody{
		Stage: p.StageWords(),
		ID:    p.ID, Name: p.Name, Version: p.Version, Active: p.Active,
		AppliesTo: p.Scope.Describe(), Requires: p.Rules.Describe(),
		CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt,
	}
}

func (g *Gateway) listPolicies(w http.ResponseWriter, r *http.Request) {
	onlyActive := r.URL.Query().Get("active") == "1"
	var out []policyBody
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var (
				ps  []policy.Policy
				err error
			)
			if onlyActive {
				ps, err = policy.Active(ctx, tx)
			} else {
				ps, err = policy.List(ctx, tx)
			}
			if err != nil {
				return err
			}
			out = make([]policyBody, 0, len(ps))
			for _, p := range ps {
				out = append(out, toPolicyBody(p))
			}
			return nil
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list policies")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policies": out,
		// The catalogue travels with the list so an editor does not have to
		// hold its own copy of what this platform understands.
		"rules": policy.Kinds(),
	})
}

type savePolicyInput struct {
	Name      string          `json:"name"`
	OSFamily  string          `json:"os_family"`
	Ownership string          `json:"ownership"`
	Rules     json.RawMessage `json:"rules"`
	// A stage (F7): save as a rolling version for this percentage of
	// devices, the devices with this tag, or both. Absent means live.
	RolloutPercent int    `json:"rollout_percent,omitempty"`
	RolloutTag     string `json:"rollout_tag,omitempty"`
}

func (in savePolicyInput) stage() *policy.Stage {
	if in.RolloutPercent == 0 && strings.TrimSpace(in.RolloutTag) == "" {
		return nil
	}
	return &policy.Stage{Percent: in.RolloutPercent, Tag: strings.TrimSpace(in.RolloutTag)}
}

func (g *Gateway) savePolicy(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())

	var in savePolicyInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "the policy could not be read")
		return
	}

	var out policy.Policy
	var undelivered []string
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var serr error
			out, serr = policy.Save(ctx, tx, policy.SaveInput{
				Name:      in.Name,
				Scope:     policy.Scope{OSFamily: in.OSFamily, Ownership: in.Ownership},
				Body:      in.Rules,
				CreatedBy: res.Subject,
				Stage:     in.stage(),
			})
			if serr != nil {
				return serr
			}
			undelivered, serr = g.deliverAndroidPolicy(ctx, tx)
			return serr
		})
	if err != nil {
		status, msg := policyStatusFor(err)
		writeError(w, status, msg)
		return
	}
	g.log.Info("policy saved", "tenant", res.Tenant.Slug,
		"policy", out.Label(), "by", res.Subject)
	body := toPolicyBody(out)
	body.AndroidJudgedOnly = undelivered
	writeJSON(w, http.StatusCreated, body)
}

func (g *Gateway) retirePolicy(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	if name == "" {
		writeError(w, http.StatusNotFound, "no such policy")
		return
	}
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return policy.Retire(ctx, tx, name)
		})
	if errors.Is(err, policy.ErrNoSuchPolicy) {
		writeError(w, http.StatusNotFound, "no such live policy")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not retire the policy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"retired": name})
}

func (g *Gateway) rollbackPolicy(w http.ResponseWriter, r *http.Request) {
	res := ResolutionFrom(r.Context())
	name := strings.TrimSpace(r.PathValue("name"))
	var in struct {
		Version int `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || in.Version <= 0 {
		writeError(w, http.StatusBadRequest, "say which version to restore")
		return
	}
	var out policy.Policy
	var undelivered []string
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var rerr error
			out, rerr = policy.Rollback(ctx, tx, name, in.Version, res.Subject)
			if rerr != nil {
				return rerr
			}
			undelivered, rerr = g.deliverAndroidPolicy(ctx, tx)
			return rerr
		})
	if errors.Is(err, policy.ErrNoSuchPolicy) {
		writeError(w, http.StatusNotFound, "no such policy version")
		return
	}
	if err != nil {
		status, msg := policyStatusFor(err)
		writeError(w, status, msg)
		return
	}
	g.log.Info("policy rolled back", "tenant", res.Tenant.Slug, "policy", out.Label(),
		"from", in.Version, "by", res.Subject)
	body := toPolicyBody(out)
	body.AndroidJudgedOnly = undelivered
	writeJSON(w, http.StatusCreated, body)
}

// stageChange is promote or halt, through the API.
func (g *Gateway) stageChange(promote bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := ResolutionFrom(r.Context())
		name := strings.TrimSpace(r.PathValue("name"))
		var out policy.Policy
		err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
			func(ctx context.Context, tx *data.Tx) error {
				var serr error
				if promote {
					out, serr = policy.Promote(ctx, tx, name, res.Subject)
				} else {
					out, serr = policy.Halt(ctx, tx, name, res.Subject)
				}
				if serr != nil {
					return serr
				}
				_, serr = g.deliverAndroidPolicy(ctx, tx)
				return serr
			})
		if errors.Is(err, policy.ErrNoSuchPolicy) {
			writeError(w, http.StatusNotFound, "no rolling version of that policy")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "the stage could not be changed")
			return
		}
		writeJSON(w, http.StatusOK, toPolicyBody(out))
	}
}

// setTags replaces a device's tags, the groups a rollout stages by.
func (g *Gateway) setTags(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	var in struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "tags are a list of words")
		return
	}
	var tags []string
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var terr error
			tags, terr = data.SetTags(ctx, tx, id, in.Tags)
			return terr
		})
	if errors.Is(err, data.ErrNoSuchDevice) {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), "data: "))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tags": tags})
}

func (g *Gateway) listTemplates(w http.ResponseWriter, r *http.Request) {
	type tb struct {
		Key       string          `json:"key"`
		Title     string          `json:"title"`
		Why       string          `json:"why"`
		OSFamily  string          `json:"os_family,omitempty"`
		Ownership string          `json:"ownership,omitempty"`
		Rules     json.RawMessage `json:"rules"`
	}
	var out []tb
	for _, t := range policy.Templates() {
		out = append(out, tb{Key: t.Key, Title: t.Title, Why: t.Why,
			OSFamily: t.Scope.OSFamily, Ownership: t.Scope.Ownership, Rules: json.RawMessage(t.Body)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": out})
}

// effectiveFor answers the question an administrator actually asks when a
// device is red: what is this laptop being held to, and by which policy.
func (g *Gateway) effectivePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	var (
		requires []string
		from     []string
		found    bool
	)
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			d, derr := data.GetDevice(ctx, tx, id)
			if derr != nil {
				return nil // another tenant's device is simply not there
			}
			found = true
			rules, applied, eerr := policy.EffectiveForDevice(ctx, tx, d.ID, d.OSFamily, d.Ownership, d.Tags)
			if eerr != nil {
				return eerr
			}
			requires = rules.Describe()
			for _, p := range applied {
				from = append(from, p.Label())
			}
			return nil
		})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not work out the policy")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	if requires == nil {
		requires = []string{}
	}
	if from == nil {
		from = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"requires": requires, "policies": from})
}

func policyStatusFor(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, policy.ErrUnknownRule), errors.Is(err, policy.ErrBadValue),
		errors.Is(err, policy.ErrBadScope), errors.Is(err, policy.ErrBadName),
		errors.Is(err, policy.ErrConfigScope), errors.Is(err, catalog.ErrUnknown), errors.Is(err, catalog.ErrBadValue):
		// These are things a person typed, so the message is the one they
		// need rather than a generic refusal.
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, policy.ErrNoSuchPolicy):
		return http.StatusNotFound, "no such policy"
	default:
		return http.StatusInternalServerError, "the policy could not be saved"
	}
}
