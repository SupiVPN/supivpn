// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
    "context"
    "crypto/tls"
    "encoding/base64"
    "fmt"
    "html/template"
    "io"
    "log"
    "net"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/beevik/etree"
    "supivpn/internal/profile"
    "supivpn/internal/saml"
)

// Explicitly interactive: neither this test nor the mock IdP opens the browser.
// Only the actual desktop client can initiate the second browser request.
func TestOpenVPNConnectExpiryManual(t *testing.T) {
    if os.Getenv("SUPIVPN_TEST_CONNECT") != "1" {
        t.Skip("interactive OpenVPN Connect test; make test-connect")
    }
    binary, hook := os.Getenv("SUPIVPN_TEST_OPENVPN"), os.Getenv("SUPIVPN_TEST_AGENT")
    if binary == "" || hook == "" { t.Fatal("isolated OpenVPN test image required") }
    dir := t.TempDir()
    if err := os.Chmod(dir,0700); err != nil {t.Fatal("test directory permissions")}
    ca := testVPNCertificate(t, dir)
    key := filepath.Join(dir, "wrapping.key")
    issuer := profile.Issuer{OpenVPN: binary}
    if err := issuer.EnsureServerKey(context.Background(), key); err != nil { t.Fatal(err) }
    socket := filepath.Join(dir, "management.sock")
    listener, err := net.Listen("unix", socket)
    if err != nil { t.Fatal(err) }
    defer listener.Close()
    server := strings.NewReplacer(
        "/etc/supivpn/tls/crt.pem", filepath.Join(dir,"crt.pem"),
        "extra-certs /etc/supivpn/tls/chain.pem", "# isolated test CA",
        "/etc/supivpn/tls/key.pem", filepath.Join(dir,"key.pem"),
        "/etc/ssl/certs/ca-certificates.crt", filepath.Join(dir,"ca.pem"),
        "/var/lib/supivpn/tls-crypt-v2-server.key", key,
        "/run/supivpn/management.sock", socket,
        "/opt/supivpn/supivpn", hook,
        "verb 2", "verb 3",
    ).Replace(openVPNServerTemplate)
    path := filepath.Join(dir,"server.conf")
    writeTestFile(t,path,[]byte(server))
    serverLog := startProtocolProcess(t,binary,"--config",path)
    listener.(*net.UnixListener).SetDeadline(time.Now().Add(10*time.Second))
    conn,err := listener.Accept()
    if err != nil { t.Fatal("OpenVPN management unavailable") }
    m := newManagement(conn)
    defer m.close()
    if err=m.negotiate(); err!=nil {t.Fatal(err)}
    if err=m.command("state on");err!=nil{t.Fatal(err)}
    if err=m.command("hold release");err!=nil{t.Fatal(err)}
    waitProtocol(t,serverLog,"Initialization Sequence Completed")

    signer,md := testIdP(t)
    md.IDPSSODescriptors[0].SingleSignOnServices[0].Location="https://localhost:18443/test-idp"
    a,_:=testApp(t,md)
    a.management.close()
    a.origin,_=url.Parse("https://localhost:18443")
    a.sp.EntityID=a.origin.String()+"/saml/metadata"
    a.sp.MetadataURL=*a.origin.JoinPath("saml/metadata")
    a.sp.AcsURL=*a.origin.JoinPath("saml/acs")
    a.config=groupConfig()
    a.config.SessionSeconds=120
    a.connections,a.tickets=map[uint64]*connection{},map[string]*connection{}
    a.pools=newPoolAllocator(a.config)
    a.attach(m)
    browser:=&connectBrowserFixture{app:a,signer:signer,seen:map[string]bool{}}
    mux:=http.NewServeMux()
    mux.HandleFunc("/test-idp",browser.idp)
    mux.Handle("/",a.handler())
    httpServer:=&http.Server{Addr:":18443",Handler:mux,ReadHeaderTimeout:5*time.Second,
        ReadTimeout:10*time.Second,WriteTimeout:10*time.Second,IdleTimeout:30*time.Second,
        MaxHeaderBytes:16<<10,TLSConfig:&tls.Config{MinVersion:tls.VersionTLS12},
        ErrorLog:log.New(io.Discard,"",0)}
    https,err:=net.Listen("tcp",httpServer.Addr)
    if err!=nil{t.Fatal("test HTTPS port unavailable")}
    defer httpServer.Close()
    go func(){_ = httpServer.ServeTLS(https,filepath.Join(dir,"crt.pem"),filepath.Join(dir,"key.pem"))}()

    // Publish only an ephemeral test profile. No deployment keys/metadata are read.
    if strings.Count(openVPNClientTemplate,"remote supivpn.example.test 1194")!=1 {t.Fatal("test remote template changed")}
    client:=strings.Replace(openVPNClientTemplate,"remote supivpn.example.test 1194","remote 127.0.0.1 11194",1)
    start,end:=strings.Index(client,"<ca>"),strings.Index(client,"</ca>")
    if start<0 || end<start{t.Fatal("CA block missing")}
    client=client[:start]+"<ca>\n"+string(ca)+"</ca>"+client[end+len("</ca>"):]
    client="verify-x509-name localhost name\n"+client
    out:="/out/connect-test.ovpn"
    if err=issuer.Issue(context.Background(),key,[]byte(client),out);err!=nil{t.Fatal("test profile issuance failed")}
    defer os.Remove(out)
    t.Log("READY_FOR_CONNECT: import local/connect-test/connect-test.ovpn; connect, then authorize in the browser.")
    t.Log("Session=120s. Wait for disconnect, then authorize the SECOND automatic browser window.")
    t.Log("Keep ping 10.203.0.1 running. Do not reconnect or open a login URL manually.")

    ticker:=time.NewTicker(time.Second)
    defer ticker.Stop()
    deadline:=time.NewTimer(20*time.Minute)
    defer deadline.Stop()
    var first *connection
    var oldTicket string
    var firstExpiry time.Time
    var completedAt time.Time
    disconnected:=false
    for {
        select {
        case e,ok:=<-m.events:
            if !ok{t.Fatal("OpenVPN management disconnected")}
            if e.kind=="CONNECT" && first!=nil && time.Now().Before(firstExpiry) {
                t.Fatal("client reconnected before session expiry")
            }
            a.handleEvent(e)
            if e.kind=="ESTABLISHED" {
                a.mu.Lock()
                current:=a.connections[e.cid]
                if current==nil {a.mu.Unlock();t.Fatal("missing established connection")}
                if first==nil {
                    first,oldTicket,firstExpiry=current,current.ticket,current.expires
                    t.Logf("CONNECTED cid=%d address=%s; wait 120 seconds for automatic reconnect.",e.cid,current.address)
                } else {
                    if !disconnected || current.cid==first.cid || current.ticket==oldTicket ||
                        a.connections[first.cid]!=nil || len(a.pools.leases)!=1 || browser.visits<2 {
                        a.mu.Unlock();t.Fatal("fresh connection/browser/slot sequence incomplete")
                    }
                    completedAt=time.Now()
                    t.Logf("RECONNECTED cid=%d address=%s with fresh SAML; check ping and Connect dialog for 30 seconds.",e.cid,current.address)
                }
                a.mu.Unlock()
            }
            if e.kind=="DISCONNECT" && first!=nil && e.cid==first.cid {
                a.mu.Lock()
                released:=a.connections[first.cid]==nil
                _,oldLease:=a.pools.leases[first.cid]
                a.mu.Unlock()
                if time.Now().Before(firstExpiry) || !released || oldLease {
                    t.Fatal("old session disconnected early or kept its address")
                }
                disconnected=true
                t.Log("SESSION_EXPIRED: old tunnel removed; waiting for automatic client reconnect and browser login.")
            }
        case <-ticker.C:
            a.expire()
            if !completedAt.IsZero() && time.Since(completedAt)>=30*time.Second {
                a.mu.Lock()
                active:=0
                for _,c:=range a.connections {if c.active && !c.closing {active++}}
                healthy:=a.readyLocked()
                a.mu.Unlock()
                if active!=1 || !healthy {t.Fatal("new session did not remain healthy")}
                t.Log("PASS: expiry disconnected old tunnel, released IP, then new CID and fresh browser SAML established a healthy tunnel.")
                return
            }
        case <-m.done:t.Fatal("OpenVPN pair stopped")
        case <-deadline.C:t.Fatal("manual test not completed within 20 minutes")
        }
    }
}

type connectBrowserFixture struct {
    app *testApplication
    signer *saml.ServiceProvider
    // Protected by app.mu, like the connection snapshots below.
    seen map[string]bool
    visits int
}

var connectIDPPage=template.Must(template.New("idp").Parse(`<!doctype html><html><meta charset="utf-8">
<title>SupiVPN local browser test</title><h1>{{.Title}}</h1>
<p>Local test identity only. No Okta credentials are needed.</p>
<p>{{.Instructions}}</p><form method="post" action="{{.ACS}}">
<input type="hidden" name="RelayState" value="{{.Ticket}}">
<input type="hidden" name="SAMLResponse" value="{{.Response}}">
<button type="submit">This window opened automatically — authorize test user</button>
</form></html>`))

func (b *connectBrowserFixture) idp(w http.ResponseWriter,r *http.Request) {
    w.Header().Set("Cache-Control","no-store")
    w.Header().Set("Referrer-Policy","no-referrer")
    w.Header().Set("Content-Security-Policy","default-src 'none'; form-action 'self'; frame-ancestors 'none'")
    if r.Method!="GET" || r.Host!="localhost:18443" {http.NotFound(w,r);return}
    ticket:=r.URL.Query().Get("RelayState")
    a:=b.app
    a.mu.Lock()
    c:=a.tickets[ticket]
    if c==nil || c.requestID=="" || !a.now().Before(c.expires) || c.closing || c.active {
        a.mu.Unlock();http.Error(w,"Test login expired",410);return
    }
    requestID,revision:=c.requestID,c.revision
    if !b.seen[ticket] {b.visits++;b.seen[ticket]=true}
    visit:=b.visits
    a.mu.Unlock()
    assertion:=groupAssertionFor(a,coreGroup)
    assertion.ID=fmt.Sprintf("connect-test-assertion-%d",revision)
    assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo=requestID
    response:=saml.Response{ID:fmt.Sprintf("connect-test-response-%d",revision),InResponseTo:requestID,
        Version:"2.0",IssueInstant:time.Now().UTC(),Destination:a.sp.AcsURL.String(),Issuer:&assertion.Issuer,
        Status:saml.Status{StatusCode:saml.StatusCode{Value:"urn:oasis:names:tc:SAML:2.0:status:Success"}},Assertion:assertion}
    signing,err:=saml.GetSigningContext(b.signer)
    if err!=nil{http.Error(w,"Test signing failed",500);return}
    element,err:=signing.SignEnveloped(response.Element())
    if err!=nil{http.Error(w,"Test signing failed",500);return}
    doc:=etree.NewDocument();doc.SetRoot(element)
    data,err:=doc.WriteToBytes()
    if err!=nil{http.Error(w,"Test response failed",500);return}
    title,instructions:="Initial login","Authorize once, keep Connect connected and wait 120 seconds."
    if visit>=2 {
        title="New login after session expiry"
        instructions="Authorize only if Connect reconnected and opened this page automatically. Then check that ping recovers and the authentication dialog closes."
    }
    w.Header().Set("Content-Type","text/html; charset=utf-8")
    _=connectIDPPage.Execute(w,struct{Title,Instructions,ACS,Ticket,Response string}{
        title,instructions,a.sp.AcsURL.String(),ticket,base64.StdEncoding.EncodeToString(data)})
}
