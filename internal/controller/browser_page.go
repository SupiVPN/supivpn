// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// One small, static stylesheet is embedded in each response. Its exact CSP hash
// permits this style only: no scripts, external assets, fonts or style attributes.
const browserCSS = `
:root{color-scheme:dark;font-family:Arial,Helvetica,sans-serif;background:#090d0b;color:#f1f4ee}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;padding:40px 24px;display:grid;place-items:center}
.shell{width:100%;max-width:660px}
.brand{display:flex;align-items:center;gap:10px;font-size:25px;font-weight:700;letter-spacing:-1px}
.brand svg{width:28px;height:32px;color:#68f548}
.accent{color:#68f548}
svg{fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
header{padding:0 0 25px;border-bottom:1px solid #26312a}
.card{margin:28px 0 24px;padding:36px;border:1px solid #26312a;border-radius:12px;background:#101612}
.symbol{display:grid;place-items:center;width:56px;height:56px;border:1px solid #385534;border-radius:50%;background:#172315;color:#68f548;margin-bottom:26px}
.symbol svg{width:26px;height:26px}
.eyebrow{color:#a2ada4;font:11px/1.6 "Courier New",monospace;letter-spacing:1.5px;text-transform:uppercase;margin:0 0 12px}
h1{margin:0 0 20px;font-size:clamp(30px,5vw,44px);font-weight:600;line-height:1.08;letter-spacing:-1.5px;overflow-wrap:anywhere}
h1.welcome{font-size:clamp(46px,8vw,64px);letter-spacing:-3px}
.description{margin:0;color:#c2ccc3;font-size:17px;line-height:1.65;overflow-wrap:anywhere}
.notice{margin:24px 0 0;padding:16px 18px;border-left:2px solid #68f548;background:#172018;color:#d7e2d7;font-size:14px;line-height:1.65}
form{margin:0}
.button{display:flex;align-items:center;justify-content:space-between;gap:18px;width:100%;min-height:52px;margin-top:28px;padding:15px 18px;border:1px solid #68f548;border-radius:5px;background:#68f548;color:#091009;font:700 15px/1.5 Arial,Helvetica,sans-serif;text-align:left;text-decoration:none;cursor:pointer}
.button:hover{background:#90ff76;border-color:#90ff76}
.button svg{flex-shrink:0;width:20px;height:20px}
a:focus-visible,button:focus-visible{outline:3px solid #f1f4ee;outline-offset:5px}
.secondary{margin:22px 0 0;color:#a2ada4;font-size:14px;line-height:1.7}
.secondary a{color:#f1f4ee;text-underline-offset:4px}
.secondary a:hover{color:#68f548}
footer{display:flex;flex-wrap:wrap;gap:8px 24px;justify-content:space-between;color:#a2ada4;font-size:12px;line-height:1.8}
footer p{margin:0}
::selection{background:#68f548;color:#090d0b}
@media(max-width:480px){body{padding:24px 18px}.card{padding:26px 22px;margin-top:22px}.description{font-size:16px}footer{display:block}header{padding-bottom:20px}}
@media(forced-colors:active){.card,.symbol,.notice,.button{border:1px solid CanvasText}.accent,.symbol{color:CanvasText}}
`

type browserPageData struct {
	Kind, Title, Eyebrow, Message, Notice      string
	Action, Token, ImportAddress, DownloadPath string
}

var browserStylePolicy = func() string {
	digest := sha256.Sum256([]byte(browserCSS))
	return "; style-src 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
}()

var browserPage = template.Must(template.New("browser-page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark"><meta name="theme-color" content="#090d0b">
<title>{{.Title}} — SupiVPN</title><style>` + browserCSS + `</style></head>
<body><div class="shell">
<header><div class="brand"><svg viewBox="0 0 32 36" aria-hidden="true"><path d="M16 2 29 7v10c0 8-7 14-13 17C10 31 3 25 3 17V7Z"/><path d="m9 17 7-7 7 7M16 17v9"/></svg><span>Supi<span class="accent">VPN</span></span></div></header>
<main class="card" aria-labelledby="page-title">
<div class="symbol" aria-hidden="true"><svg viewBox="0 0 24 24">
{{if eq .Kind "verified"}}<path d="m5 12 4 4L19 6"/>
{{else if eq .Kind "import"}}<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>
{{else if eq .Kind "error"}}<path d="M12 3 3 20h18ZM12 9v4m0 3v.1"/>
{{else}}<path d="M12 2 21 6v6c0 5-5 8-9 10-4-2-9-5-9-10V6Z"/><path d="m8 12 3 3 5-6"/>{{end}}
</svg></div>
<p class="eyebrow">{{.Eyebrow}}</p>
{{if eq .Kind "welcome"}}<h1 id="page-title" class="welcome">Go <span class="accent">Supi!</span></h1>{{else}}<h1 id="page-title">{{.Title}}</h1>{{end}}
<p class="description">{{.Message}}</p>
{{if .Notice}}<p class="notice">{{.Notice}}</p>{{end}}
{{if eq .Kind "confirmation"}}<form method="post" action="{{.Action}}"><input type="hidden" name="confirmation" value="{{.Token}}"><button class="button" type="submit">Continue to sign in <span aria-hidden="true">→</span></button></form>
{{else if eq .Kind "welcome"}}<a class="button" href="{{.Action}}">Continue to sign in <span aria-hidden="true">→</span></a>
{{else if eq .Kind "import"}}<a class="button" href="openvpn://import-profile/{{.ImportAddress}}">Open in OpenVPN Connect <span aria-hidden="true">↗</span></a><p class="secondary">Using Linux? <a href="{{.DownloadPath}}">Download your .ovpn profile</a> and import it into your VPN client.</p>
{{else if eq .Kind "verified"}}<p class="secondary">You can close this browser tab. Your VPN client will confirm when the tunnel is connected.</p>{{end}}
</main><footer><p>Your team. Your tunnel. Your rules.</p><p>Go Supi!</p></footer>
</div></body></html>`))

func renderBrowserPage(w http.ResponseWriter, status int, page browserPageData) {
	var body bytes.Buffer
	if err := browserPage.Execute(&body, page); err != nil {
		http.Error(w, "Page unavailable", http.StatusInternalServerError)
		return
	}
	policy := "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"
	if page.Kind == "confirmation" && w.Header().Get("Content-Security-Policy") != "" {
		// login() supplies the already validated same-origin/IdP form policy.
		policy = w.Header().Get("Content-Security-Policy")
	}
	w.Header().Set("Content-Security-Policy", policy+browserStylePolicy)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	if w.Header().Get("Referrer-Policy") == "" {
		w.Header().Set("Referrer-Policy", "no-referrer")
	}
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}

func acceptsBrowserHTML(r *http.Request) bool {
	for _, item := range strings.Split(r.Header.Get("Accept"), ",") {
		media, params, err := mime.ParseMediaType(strings.TrimSpace(item))
		if err != nil || media != "text/html" {
			continue
		}
		if q, exists := params["q"]; exists {
			quality, err := strconv.ParseFloat(q, 64)
			if err != nil || !(quality > 0 && quality <= 1) {
				continue
			}
		}
		return true
	}
	return false
}

// Preserve text/status responses for clients that do not explicitly ask for
// HTML. Never reflect request fields, SAML, identities or backend error strings.
func browserMessage(w http.ResponseWriter, r *http.Request, message string, status int) {
	w.Header().Add("Vary", "Accept")
	if !acceptsBrowserHTML(r) {
		if status >= 400 {
			http.Error(w, message, status)
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(status)
			fmt.Fprintln(w, message)
		}
		return
	}
	page := browserPageData{Kind: "error", Title: "Sign-in wasn't completed.", Eyebrow: "Access not granted", Message: message}
	if status == http.StatusGone || status == http.StatusConflict {
		page.Title, page.Eyebrow = "Let's start again.", "A fresh sign-in is needed"
	} else if status >= 500 {
		page.Title, page.Eyebrow = "A little trouble connecting.", "Please try again"
	} else if status < 400 {
		page.Kind, page.Title, page.Eyebrow = "verified", "Sign-in verified.", "Back to your VPN client"
		page.Message = "Your organization has verified this sign-in. Return to your VPN client to finish connecting."
		if status == http.StatusAccepted {
			page.Message = "Your sign-in is verified. The VPN server is still processing the connection."
			if message == connectionRetryMessage {
				page.Kind, page.Title, page.Eyebrow = "waiting", "Waiting for your previous connection.", "One automatic retry"
				page.Message = message
			}
		}
	}
	renderBrowserPage(w, status, page)
}
