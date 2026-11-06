package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"platform/internal/data"
	"platform/internal/notify"
)

// T10: the export, sent to a bucket the tenant names instead of downloaded.
//
// Any S3-compatible store (AWS S3, Cloudflare R2, MinIO, Backblaze B2,
// Wasabi) takes a PutObject signed with AWS Signature Version 4, which is
// a few lines of HMAC and no SDK. The credentials are typed for this one
// send and never kept, logged or audited: the audit line names the bucket
// and the key, not the secret. The endpoint is held to the same rule as
// a webhook: https, resolved to an address on the public internet before
// a byte is sent, so "my bucket" cannot be a name that points inside this
// platform's own network.

var errBucketRefused = errors.New("the bucket refused the upload")

// bucketTarget is one send's worth of configuration.
type bucketTarget struct {
	Endpoint, Bucket, Key, Region string
	AccessKey, SecretKey          string
}

func (b bucketTarget) check(allowPrivate bool) error {
	u, err := url.Parse(strings.TrimSpace(b.Endpoint))
	if err != nil || u.Host == "" {
		return errors.New("the endpoint is not a web address")
	}
	if u.User != nil {
		return errors.New("put no username or password in the endpoint")
	}
	if u.Scheme != "https" && !(allowPrivate && u.Scheme == "http") {
		return errors.New("the endpoint is an https:// address")
	}
	if b.Bucket == "" || strings.ContainsAny(b.Bucket, "/ \\") {
		return errors.New("the bucket name is one word, no slashes")
	}
	if b.Key == "" || strings.HasPrefix(b.Key, "/") {
		return errors.New("the object key is a path inside the bucket")
	}
	if b.AccessKey == "" || b.SecretKey == "" {
		return errors.New("the access key id and secret access key are both needed")
	}
	return nil
}

// bucketClient dials only addresses the guard allows: every address the
// host resolves to is checked before the connection is made, so a name
// that resolves to one public and one private address is refused as a
// whole. The control --break-bucketssrf skips the check.
func (g *Gateway) bucketClient() *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("the endpoint's name does not resolve")
				}
				for _, ip := range ips {
					if !g.allowPrivateBuckets && !notify.PublicIP(ip.IP) {
						return nil, errors.New("that endpoint resolves to an address inside this platform's own network")
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
			},
		},
	}
}

// putObject is PutObject with Signature Version 4, path-style, the
// payload hashed into the signature so the bucket can refuse a body that
// is not the one signed.
func (g *Gateway) putObject(ctx context.Context, t bucketTarget, body []byte, now time.Time) error {
	base := strings.TrimRight(strings.TrimSpace(t.Endpoint), "/")
	u, err := url.Parse(base + "/" + t.Bucket + "/" + t.Key)
	if err != nil {
		return err
	}
	region := t.Region
	if region == "" {
		region = "us-east-1"
	}
	payloadHash := hex.EncodeToString(sha256Sum(body))
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", amzDate)

	// The canonical request, with the three headers every S3-compatible
	// store expects signed: host, the payload hash, the date.
	canonicalURI := u.EscapedPath()
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonical := strings.Join([]string{
		http.MethodPut, canonicalURI, "",
		"host:" + u.Host, "x-amz-content-sha256:" + payloadHash, "x-amz-date:" + amzDate, "",
		signedHeaders, payloadHash,
	}, "\n")
	scope := date + "/" + region + "/s3/aws4_request"
	toSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(sha256Sum([]byte(canonical))),
	}, "\n")
	signature := hex.EncodeToString(hmacSHA256(sigV4Key(t.SecretKey, date, region, "s3"), []byte(toSign)))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		t.AccessKey, scope, signedHeaders, signature))

	resp, err := g.bucketClient().Do(req)
	if err != nil {
		return fmt.Errorf("the bucket could not be reached: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%w: HTTP %d", errBucketRefused, resp.StatusCode)
	}
	return nil
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// sigV4Key is the derived signing key: the secret, then the date, the
// region, the service and the terminal string, each HMAC'd into the next.
func sigV4Key(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	k = hmacSHA256(k, []byte(region))
	k = hmacSHA256(k, []byte(service))
	return hmacSHA256(k, []byte("aws4_request"))
}

// consoleExportBucket is the form: make the export, send it, say where it
// went. The credentials live in this request and nowhere else.
func (g *Gateway) consoleExportBucket(w http.ResponseWriter, r *http.Request, res Resolution) {
	t := bucketTarget{
		Endpoint:  strings.TrimSpace(r.FormValue("endpoint")),
		Bucket:    strings.TrimSpace(r.FormValue("bucket")),
		Region:    strings.TrimSpace(r.FormValue("region")),
		AccessKey: strings.TrimSpace(r.FormValue("access_key")),
		SecretKey: strings.TrimSpace(r.FormValue("secret_key")),
	}
	prefix := strings.Trim(strings.TrimSpace(r.FormValue("prefix")), "/")
	now := time.Now().UTC()
	t.Key = res.Tenant.Slug + "-export-" + now.Format("2006-01-02T150405Z") + ".zip"
	if prefix != "" {
		t.Key = prefix + "/" + t.Key
	}
	if err := t.check(g.allowPrivateBuckets); err != nil {
		back(w, r, "/identity", "Not sent. "+err.Error()+".")
		return
	}
	var body []byte
	err := g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			var e error
			body, e = g.exportTenant(ctx, tx, res.Subject)
			return e
		})
	if err != nil {
		g.log.Error("export for bucket", "tenant", res.Tenant.Slug, "err", err)
		back(w, r, "/identity", "Not sent. The export could not be made.")
		return
	}
	if err := g.putObject(r.Context(), t, body, now); err != nil {
		// The reason, without the endpoint's own words beyond a status:
		// a bucket's error body can carry the request's details back.
		g.log.Warn("export to bucket failed", "tenant", res.Tenant.Slug, "bucket", t.Bucket, "err", err)
		back(w, r, "/identity", "Not sent. "+err.Error()+". Nothing was recorded as sent.")
		return
	}
	where := strings.TrimRight(t.Endpoint, "/") + "/" + t.Bucket + "/" + t.Key
	err = g.store.WithTenant(r.Context(), ClaimFrom(r.Context()),
		func(ctx context.Context, tx *data.Tx) error {
			return data.AppendAudit(ctx, tx, "export.sent",
				fmt.Sprintf("bucket:%s bytes:%d by:%s", where, len(body), res.Subject))
		})
	if err != nil {
		g.log.Error("export sent but not audited", "tenant", res.Tenant.Slug, "err", err)
	}
	g.log.Info("tenant export sent to bucket", "tenant", res.Tenant.Slug, "bytes", len(body), "by", res.Subject)
	back(w, r, "/identity", fmt.Sprintf("Sent: %d bytes to %s. Recorded in the audit log.", len(body), where))
}
