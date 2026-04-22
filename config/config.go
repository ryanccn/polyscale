package config

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/charmbracelet/log"
)

type Config struct {
	Servers              []ConfigServer
	ControlURL           string
	CertificateAuthority ConfigCA
}

type ConfigCA struct {
	Cert string
	Key  string
}

type ConfigServer struct {
	Name string
	Src  url.URL
	Dst  string

	TLS                 ConfigServerTLSOption
	Funnel              bool
	Ephemeral           bool
	ProxyProtocol       bool
	AddTailscaleHeaders bool
}

type ConfigServerTLSOption int

func (tls ConfigServerTLSOption) String() string {
	switch tls {
	case TLSNone:
		return "none"
	case TLSPolyscale:
		return "polyscale"
	case TLSTailscale:
		return "tailscale"
	}

	return "unknown"
}

const (
	TLSNone ConfigServerTLSOption = iota
	TLSPolyscale
	TLSTailscale
)

func (s *ConfigServer) UnmarshalJSON(b []byte) error {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}

	if value, ok := v["name"].(string); ok {
		s.Name = value
	} else {
		return fmt.Errorf("config/?: missing `name`")
	}

	if value, ok := v["src"].(string); ok {
		srcUrl, err := url.ParseRequestURI(value)
		if err != nil {
			return err
		}

		s.Src = *srcUrl
	} else {
		return fmt.Errorf("config/%v: missing `src`", s.Name)
	}

	if dst, ok := v["dst"].(string); ok {
		s.Dst = dst
	} else {
		return fmt.Errorf("config/%v: missing `dst`", s.Name)
	}

	if value, ok := v["tls"].(bool); ok {
		if value {
			s.TLS = TLSPolyscale
		} else {
			s.TLS = TLSNone
		}
	} else if value, ok := v["tls"].(string); ok {
		switch value {
		case "tailscale":
			s.TLS = TLSTailscale
		case "polyscale":
			s.TLS = TLSPolyscale
		default:
			return fmt.Errorf("config/%v: invalid `tls` value: %+v", s.Name, value)
		}
	} else if v["tls"] == nil {
		s.TLS = TLSNone
	} else {
		return fmt.Errorf("config/%v: invalid `tls` value: %+v", s.Name, v["tls"])
	}

	if s.TLS != TLSNone && (s.Src.Scheme == "udp" || s.Src.Scheme == "unixgram") {
		return fmt.Errorf("config/%v: `tls` cannot be used with UDP", s.Name)
	}

	if value, ok := v["funnel"].(bool); ok {
		s.Funnel = value
	} else if v["funnel"] == nil {
		s.Funnel = false
	} else {
		return fmt.Errorf("config/%v: invalid `funnel` value: %+v", s.Name, v["funnel"])
	}

	if s.Funnel && (s.Src.Scheme == "udp" || s.Src.Scheme == "unixgram") {
		return fmt.Errorf("config/%v: `funnel` cannot be used with UDP", s.Name)
	}

	if v["tls"] != nil && s.Funnel {
		log.Warnf("config/%v: `tls` is ignored when `funnel` is `true` and should not be set", s.Name)
	}

	if value, ok := v["ephemeral"].(bool); ok {
		s.Ephemeral = value
	} else if v["ephemeral"] == nil {
		s.Ephemeral = true
	} else {
		return fmt.Errorf("config/%v: invalid `ephemeral` value: %+v", s.Name, v["ephemeral"])
	}

	if value, ok := v["proxyProtocol"].(bool); ok {
		s.ProxyProtocol = value
	} else if v["proxyProtocol"] == nil {
		s.ProxyProtocol = false
	} else {
		return fmt.Errorf("config/%v: invalid `proxyProtocol` value: %+v", s.Name, v["proxyProtocol"])
	}

	if s.ProxyProtocol && s.Src.Scheme != "tcp" && s.Src.Scheme != "unix" && s.Src.Scheme != "unixpacket" {
		return fmt.Errorf("config/%v: `proxyProtocol` can only be used with TCP", s.Name)
	}

	if value, ok := v["addTailscaleHeaders"].(bool); ok {
		s.AddTailscaleHeaders = value
	} else if v["addTailscaleHeaders"] == nil {
		s.AddTailscaleHeaders = false
	} else {
		return fmt.Errorf("config/%v: invalid `addTailscaleHeaders` value: %+v", s.Name, v["addTailscaleHeaders"])
	}

	if s.AddTailscaleHeaders && s.Src.Scheme != "http" && s.Src.Scheme != "https" && s.Src.Scheme != "unix+http" {
		return fmt.Errorf("config/%v: `addTailscaleHeaders` can only be used with HTTP", s.Name)
	}

	return nil
}
