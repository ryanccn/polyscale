package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"

	"github.com/charmbracelet/log"
	"tailscale.com/client/local"

	"github.com/ryanccn/polyscale/config"
)

// https://github.com/oauth2-proxy/oauth2-proxy/blob/bb6ff4ed147ec12e054b2e283676901943a0a4cb/pkg/upstream/http.go#L101-L118
type unixRoundTripper struct {
	Transport *http.Transport
}

func (t *unixRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Host == "" {
		req.Host = "localhost"
	}
	req.URL.Host = req.Host
	tt := t.Transport
	req = req.Clone(req.Context())
	req.URL.Scheme = "http"
	return tt.RoundTrip(req)
}

func HTTPReverseProxy(wg *sync.WaitGroup, srvConfig *config.ConfigServer, cfg *config.Config, listener net.Listener, tsLocalClient *local.Client) {
	defer wg.Done()
	defer listener.Close()

	target := srvConfig.Src
	if target.Scheme == "unix+http" {
		target.Scheme = "unix"
	}

	// https://github.com/oauth2-proxy/oauth2-proxy/blob/bb6ff4ed147ec12e054b2e283676901943a0a4cb/pkg/upstream/http.go#L127-L136
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if target.Scheme == "unix" {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, target.Scheme, target.Path)
		}

		transport.RegisterProtocol(target.Scheme, &unixRoundTripper{Transport: transport})
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(&target)
			r.SetXForwarded()
			r.Out.Host = r.In.Host

			r.Out.Header.Del("Tailscale-User-Name")
			r.Out.Header.Del("Tailscale-User-Login")
			r.Out.Header.Del("Tailscale-User-Profile-Picture")
			r.Out.Header.Del("Tailscale-User-Id")

			if srvConfig.AddTailscaleHeaders {
				tsIdentity, _ := tsLocalClient.WhoIs(r.In.Context(), r.In.RemoteAddr)

				if tsIdentity != nil {
					r.Out.Header.Set("Tailscale-User-Name", tsIdentity.UserProfile.DisplayName)
					r.Out.Header.Set("Tailscale-User-Login", tsIdentity.UserProfile.LoginName)
					r.Out.Header.Set("Tailscale-User-Profile-Picture", tsIdentity.UserProfile.ProfilePicURL)
					r.Out.Header.Set("Tailscale-User-Id", tsIdentity.UserProfile.ID.String())
				}
			}
		},
	}

	if err := http.Serve(listener, proxy); err != nil {
		log.Fatal(err)
	}
}
