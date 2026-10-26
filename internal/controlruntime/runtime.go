// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package controlruntime wires the shared controller and PostgreSQL backend.
// Deployment adapters own listeners, IAM/peer credentials and secret delivery.
package controlruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/agentapi"
	"supivpn/internal/controller"
	"supivpn/internal/gateway"
	"supivpn/internal/logging"
	"supivpn/internal/operatorapi"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
	"supivpn/internal/saml"
	"supivpn/internal/vm"
)

type Group struct {
	SessionSeconds        *int   `json:"session_seconds,omitempty"`
	MaxConnectionsPerUser int    `json:"max_connections_per_user,omitempty"`
	Name                  string `json:"name"`
	Priority              int    `json:"priority"`
}
type Config struct {
	VPNLoginConfirmation  *bool                  `json:"vpn_login_confirmation,omitempty"`
	AssertionEncryption   *saml.EncryptionConfig `json:"assertion_encryption,omitempty"`
	Logging               *logging.Config        `json:"logging,omitempty"`
	DatabaseTLS           *postgres.TLSConfig    `json:"database_tls,omitempty"`
	MaxConnectionsPerUser int                    `json:"max_connections_per_user,omitempty"`
	PublicURL             string                 `json:"public_url"`
	IDPMetadata           string                 `json:"idp_metadata"`
	SAMLGroupsAttribute   string                 `json:"saml_groups_attribute"`
	Groups                []Group                `json:"groups"`
	PendingSeconds        int                    `json:"pending_seconds"`
	SessionSeconds        int                    `json:"session_seconds"`
	VM                    *vm.Config             `json:"vm,omitempty"`
	Gateway               *gateway.Config        `json:"gateway,omitempty"`
	Profile               *ProfileConfig         `json:"profile,omitempty"`
}

type ProfileConfig struct {
	Binding      string `json:"binding,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	ServerURL    bool   `json:"server_url,omitempty"`
	Endpoint     string `json:"endpoint"`
	TemplateFile string `json:"template_file"`
	// VM mode reads the provisioned local key. Lambda supplies a loader instead.
	ServerKeyFile string `json:"server_key_file,omitempty"`
}

func ReadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("cannot open controller configuration")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(b) > 64<<10 {
		return c, errors.New("controller configuration too large")
	}
	return ParseConfig(string(b))
}

func ParseConfig(value string) (Config, error) {
	c := Config{SessionSeconds: 43200}
	if len(value) > 64<<10 {
		return c, errors.New("controller configuration too large")
	}
	d := json.NewDecoder(strings.NewReader(value))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, errors.New("invalid controller configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("trailing controller configuration")
	}
	component := "controller"
	if c.Gateway != nil {
		component = "public"
	}
	if err := c.Logging.Validate(component); err != nil {
		return c, err
	}
	if err := c.AssertionEncryption.Validate(); err != nil {
		return c, err
	}
	if err := c.DatabaseTLS.Validate(); err != nil {
		return c, err
	}
	return c, nil
}
func (c Config) Policy() (controller.Config, *url.URL, error) {
	if err := c.AssertionEncryption.Validate(); err != nil {
		return controller.Config{}, nil, err
	}
	if c.AssertionEncryption != nil && c.AssertionEncryption.PrivateKeySecretARN != "" && (c.Gateway == nil || c.VM != nil) {
		return controller.Config{}, nil, errors.New("SAML encryption secrets require the public Lambda adapter")
	}
	if c.AssertionEncryption != nil && c.VM != nil && c.AssertionEncryption.PrivateKeyFile != "" && c.AssertionEncryption.PrivateKeyFile == c.VM.TLSPrivateKey {
		return controller.Config{}, nil, errors.New("use a dedicated SAML encryption key separate from TLS")
	}
	if err := c.DatabaseTLS.Validate(); err != nil {
		return controller.Config{}, nil, err
	}
	origin, err := url.Parse(c.PublicURL)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || (origin.Path != "" && origin.Path != "/supivpn") || origin.RawPath != "" || origin.User != nil ||
		origin.RawQuery != "" || origin.Fragment != "" || len(c.PublicURL) > 300 || strings.ContainsAny(c.PublicURL, " \t\r\n\\\"") {
		return controller.Config{}, nil, errors.New("public_url must be an HTTPS origin")
	}
	if !filepath.IsAbs(c.IDPMetadata) || c.SAMLGroupsAttribute == "" ||
		c.PendingSeconds < 30 || c.PendingSeconds > 180 || !controller.ValidSessionSeconds(c.SessionSeconds) {
		return controller.Config{}, nil, errors.New("invalid controller limits, metadata path or groups claim")
	}
	p := controller.Config{Policy: controller.Policy{SAMLGroupsAttribute: c.SAMLGroupsAttribute, MaxConnectionsPerUser: c.MaxConnectionsPerUser}, PendingSeconds: c.PendingSeconds, SessionSeconds: c.SessionSeconds, VPNLoginConfirmation: c.VPNLoginConfirmation}
	for _, g := range c.Groups {
		p.Groups = append(p.Groups, controller.Group{GroupName: g.Name, Priority: g.Priority, MaxConnectionsPerUser: g.MaxConnectionsPerUser, SessionSeconds: g.SessionSeconds})
	}
	if err = controller.ValidatePolicy(p.Policy); err != nil {
		return p, nil, err
	}
	return p, origin, nil
}

type Application struct {
	Public, Agents http.Handler
	Operations     func(context.Context, json.RawMessage) (any, error)
	Origin         *url.URL
	pool           *pgxpool.Pool
	store          *postgres.Store
}

func (a *Application) Close() { a.pool.Close() }
func (a *Application) Prune(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := a.store.Prune(ctx, 500)
	if err != nil {
		return err
	}
	return a.store.FenceExpired(ctx)
}
func Open(ctx context.Context, c Config, dsn string) (*Application, error) {
	return OpenWithPassword(ctx, c, dsn, nil)
}

func OpenWithPassword(ctx context.Context, c Config, dsn string, password func(context.Context) (string, error)) (*Application, error) {
	return OpenWithProfileKey(ctx, c, dsn, password, nil)
}

// Profile key loaders return a caller-owned buffer and are invoked only after a
// successful, consumed SAML login. Cloud-specific loaders belong to adapters.
func OpenWithProfileKey(ctx context.Context, c Config, dsn string, password func(context.Context) (string, error), key func(context.Context) ([]byte, error), fencing ...postgres.Fencer) (*Application, error) {
	return openPublic(ctx, c, dsn, password, key, nil, "", fencing...)
}

// OpenPublic constructs only browser/profile handlers with restricted DB access.
func OpenPublic(ctx context.Context, c Config, dsn string, password func(context.Context) (string, error), key func(context.Context) ([]byte, error)) (*Application, error) {
	return OpenPublicWithEncryptionKey(ctx, c, dsn, password, key, nil)
}

// OpenPublicWithEncryptionKey adds initialization-time SAML key delivery. The
// profile wrapping-key callback remains deferred until authorized issuance.
func OpenPublicWithEncryptionKey(ctx context.Context, c Config, dsn string, password func(context.Context) (string, error), key func(context.Context) ([]byte, error), encryptionKey saml.EncryptionKeyLoader) (*Application, error) {
	return openPublic(ctx, c, dsn, password, key, encryptionKey, postgres.Public)
}

func openPublic(ctx context.Context, c Config, dsn string, password func(context.Context) (string, error), key func(context.Context) ([]byte, error), encryptionKey saml.EncryptionKeyLoader, component postgres.Component, fencing ...postgres.Fencer) (*Application, error) {
	if len(fencing) > 1 {
		return nil, errors.New("multiple fencing providers")
	}
	policy, origin, err := c.Policy()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(c.IDPMetadata)
	if err != nil {
		return nil, errors.New("cannot open IdP metadata")
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	f.Close()
	if err != nil || len(b) > 1<<20 {
		return nil, errors.New("IdP metadata too large")
	}
	md, err := saml.ParseMetadata(b)
	if err != nil || md.EntityID == "" || len(md.IDPSSODescriptors) == 0 {
		return nil, errors.New("invalid IdP metadata")
	}
	sp := &saml.ServiceProvider{EntityID: origin.String() + "/saml/metadata",
		MetadataURL: *origin.JoinPath("saml/metadata"), AcsURL: *origin.JoinPath("saml/acs"),
		IDPMetadata: md, AuthnNameIDFormat: saml.UnspecifiedNameIDFormat, AllowIDPInitiated: false}
	sp.AssertionEncryption, err = c.AssertionEncryption.LoadWithKey(ctx, encryptionKey)
	if err != nil {
		return nil, err
	}
	idp, err := url.Parse(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding))
	if err != nil || idp.Scheme != "https" || idp.Host == "" || idp.User != nil {
		return nil, errors.New("IdP requires HTTPS Redirect SSO")
	}
	pool, err := postgres.OpenWithTLS(ctx, dsn, password, c.DatabaseTLS)
	if err != nil {
		return nil, err
	}
	store := postgres.New(pool)
	if len(fencing) == 1 {
		store = postgres.NewWithFencer(pool, fencing[0])
	}
	if component != "" {
		store, err = postgres.NewIsolated(ctx, pool, component, nil)
		if err != nil {
			pool.Close()
			return nil, err
		}
	}
	var downloads []controller.ProfileDownloads
	if c.Profile != nil {
		if (c.Profile.Binding == "required" || c.Profile.ServerURL) && !store.ProfileSchemaReady(ctx) {
			pool.Close()
			return nil, errors.New("profile ownership and Server URL require schema 12")
		}
		download, profileErr := profileDownload(c.Profile, key, store)
		if profileErr != nil {
			pool.Close()
			return nil, profileErr
		}
		download.Backend = postgres.NewProfileBackend(store, time.Duration(c.PendingSeconds)*time.Second)
		downloads = append(downloads, download)
	}
	control, err := controller.New(policy, origin, sp, store, time.Now, downloads...)
	if err != nil {
		pool.Close()
		return nil, err
	}
	app := &Application{Public: Bounded(control.Handler()), Origin: origin, pool: pool, store: store}
	if component == "" {
		app.Agents = agentapi.New(store, time.Duration(c.PendingSeconds)*time.Second)
		app.Operations = operatorapi.Handler(store)
	}
	return app, nil
}

func profileMaterial(c *ProfileConfig, key func(context.Context) ([]byte, error)) ([]byte, func(context.Context) ([]byte, error), error) {
	if !filepath.IsAbs(c.TemplateFile) {
		return nil, nil, errors.New("profile template must be an absolute path")
	}
	if key == nil {
		if !filepath.IsAbs(c.ServerKeyFile) {
			return nil, nil, errors.New("profile downloads require a wrapping-key source")
		}
		key = profile.KeyFile(c.ServerKeyFile)
	} else if c.ServerKeyFile != "" {
		return nil, nil, errors.New("configure only one profile wrapping-key source")
	}
	f, err := os.Open(c.TemplateFile)
	if err != nil {
		return nil, nil, errors.New("profile template unavailable")
	}
	defer f.Close()
	template, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(template) > 64<<10 {
		return nil, nil, errors.New("profile template unavailable")
	}
	return template, key, nil
}

// Request work is synchronous. Driver calls inherit the invocation deadline
// (or this shorter budget); correctness never depends on background timers.
func Bounded(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func profileIssuer(c *ProfileConfig, key func(context.Context) ([]byte, error)) (func(context.Context) ([]byte, error), error) {
	template, load, err := profileMaterial(c, key)
	if err != nil {
		return nil, err
	}
	return profile.DownloadIssuer(template, c.Endpoint, load)
}
func profileDownload(c *ProfileConfig, key func(context.Context) ([]byte, error), s *postgres.Store) (controller.ProfileDownloads, error) {
	var d controller.ProfileDownloads
	if c.Binding != "" && c.Binding != "legacy" && c.Binding != "required" {
		return d, errors.New("profile binding must be legacy or required")
	}
	if c.Binding != "required" && c.Port != 0 && c.Port != 1194 {
		return d, errors.New("legacy profiles use port 1194")
	}
	template, load, err := profileMaterial(c, key)
	if err != nil {
		return d, err
	}
	if c.Binding == "required" {
		if c.Port == 0 {
			return d, errors.New("bound profiles require an explicit port")
		}
		d.IssueForSubject, err = profile.BoundDownloadIssuer(template, c.Endpoint, c.Port, load, s.CreateProfile)
	} else {
		d.Issue, err = profile.DownloadIssuer(template, c.Endpoint, load)
	}
	if c.ServerURL {
		d.Imports = s
	}
	return d, err
}
