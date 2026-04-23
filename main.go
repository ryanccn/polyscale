// SPDX-FileCopyrightText: 2026 Ryan Cao <hello@ryanccn.dev>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"tailscale.com/tsnet"

	"github.com/ryanccn/polyscale/cert"
	"github.com/ryanccn/polyscale/config"
	"github.com/ryanccn/polyscale/proxy"
)

var (
	configPath = flag.String("config", "", "path to config file")
	tsAuthKey  = flag.String("auth-key", "", "auth key to use with Tailscale (env: `TS_AUTHKEY`)")
	logLevel   = flag.String("log-level", "", "log level")

	caCertPath    = flag.String("ca-cert", "", "path to a PEM-encoded CA cert to use with Polyscale TLS (overrides config)")
	caPrivKeyPath = flag.String("ca-key", "", "path to a PEM-encoded CA key to use with Polyscale TLS (overrides config)")

	actionClearCerts = flag.Bool("clear-certs", false, "clear stored internal CA and TLS certificates")
	actionCheck      = flag.Bool("check", false, "check if the config is valid")
)

func main() {
	flag.Parse()
	setupLogging()

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}

	if *actionClearCerts {
		certs := path.Join(userConfigDir, "polyscale", "certs")

		err = os.RemoveAll(certs)
		if err != nil {
			log.Fatal(err)
		}

		log.Infof("cleared CA and TLS certificates from %v", certs)

		return
	}

	if *configPath == "" {
		*configPath = filepath.Join(cwd, "config.json")
	}

	if *tsAuthKey == "" {
		*tsAuthKey = os.Getenv("TS_AUTHKEY")
	}
	if *tsAuthKey == "" {
		*tsAuthKey = os.Getenv("TS_AUTH_KEY")
	}

	if *tsAuthKey == "" {
		log.Fatal("at least one of `-auth-key`, `TS_AUTHKEY`, and `TS_AUTH_KEY` should be set")
	}

	configFile, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	var cfg config.Config
	if err := json.Unmarshal(configFile, &cfg); err != nil {
		log.Fatal(err)
	}

	if *caCertPath != "" {
		if *caPrivKeyPath == "" {
			log.Fatal("cannot specify `ca-cert` without `ca-key`")
		}

		caCertBytes, err := os.ReadFile(*caCertPath)
		if err != nil {
			log.Fatal(err)
		}

		cfg.CertificateAuthority.Cert = string(caCertBytes)

		caPrivKeyBytes, err := os.ReadFile(*caPrivKeyPath)
		if err != nil {
			log.Fatal(err)
		}

		cfg.CertificateAuthority.Key = string(caPrivKeyBytes)
	}

	log.Warnf("read config from %v", *configPath)

	if *actionCheck {
		os.Exit(0)
	}

	tsServers := make(map[string]*tsnet.Server)
	wg := sync.WaitGroup{}

	for _, server := range cfg.Servers {
		dataDir := path.Join(userConfigDir, "polyscale", "tsnet", server.Name)

		if err := os.MkdirAll(dataDir, 0700); err != nil {
			log.Fatal(err)
		}

		var srv *tsnet.Server
		if tsServers[server.Name] != nil {
			srv = tsServers[server.Name]
		} else {
			srv = &tsnet.Server{
				Hostname:   server.Name,
				AuthKey:    *tsAuthKey,
				Ephemeral:  server.Ephemeral,
				ControlURL: cfg.ControlURL,
				Dir:        dataDir,
				Logf: func(format string, args ...any) {
					log.WithPrefix(fmt.Sprintf("tsnet/%v", server.Name)).Debugf(format, args...)
				},
				UserLogf: func(format string, args ...any) {
					log.WithPrefix(fmt.Sprintf("tsnet/%v", server.Name)).Infof(format, args...)
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			_, err := srv.Up(ctx)
			if err != nil {
				log.Fatal(err)
			}

			tsServers[server.Name] = srv
		}

		tailscaleClient, err := srv.LocalClient()
		if err != nil {
			log.Fatal(err)
		}

		var listenTransport string
		switch server.Src.Scheme {
		case "http", "https", "unix", "unixpacket", "unix+http", "tcp":
			listenTransport = "tcp"
		case "unixgram", "udp":
			listenTransport = "udp"
		default:
			log.Fatalf("scheme %v is unsupported", server.Src.Scheme)
		}

		var tcpListener net.Listener
		var udpConns []net.PacketConn

		if listenTransport == "udp" {
			listenAddr4 := server.Dst
			listenAddr6 := server.Dst

			if port, portFound := strings.CutPrefix(server.Dst, ":"); portFound {
				if port, err := strconv.ParseUint(port, 10, 16); err == nil {
					ip4, ip6 := srv.TailscaleIPs()
					listenAddr4 = netip.AddrPortFrom(ip4, uint16(port)).String()
					listenAddr6 = netip.AddrPortFrom(ip6, uint16(port)).String()
				}
			}

			udpConn4, err := srv.ListenPacket(listenTransport, listenAddr4)
			if err != nil {
				log.Fatal(err)
			}

			udpConn6, err := srv.ListenPacket(listenTransport, listenAddr6)
			if err != nil {
				log.Fatal(err)
			}

			udpConns = []net.PacketConn{udpConn4, udpConn6}
		} else if server.Funnel {
			tcpListener, err = srv.ListenFunnel(listenTransport, server.Dst)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			tcpListener, err = srv.Listen(listenTransport, server.Dst)
			if err != nil {
				log.Fatal(err)
			}

			switch server.TLS {
			case config.TLSPolyscale:
				tcpListener = tls.NewListener(tcpListener, &tls.Config{
					GetCertificate: cert.GetCertificate(&cfg),
				})

			case config.TLSTailscale:
				tcpListener = tls.NewListener(tcpListener, &tls.Config{
					GetCertificate: tailscaleClient.GetCertificate,
				})
			}
		}

		log.Info(
			"forwarding",
			"from", []any{srv.CertDomains(), server.Dst},
			"to", server.Src.String(),
			"listenTransport", listenTransport,
			"tls", server.TLS,
			"funnel", server.Funnel,
			"ephemeral", server.Ephemeral,
			"proxyProtocol", server.ProxyProtocol,
			"addTailscaleHeaders", server.AddTailscaleHeaders,
		)

		switch server.Src.Scheme {
		case "udp", "unixgram":
			for _, conn := range udpConns {
				wg.Add(1)
				go proxy.UDPReverseProxy(&wg, &server, conn)
			}
		case "http", "https", "unix+http":
			wg.Add(1)
			go proxy.HTTPReverseProxy(&wg, &server, &cfg, tcpListener, tailscaleClient)
		default:
			wg.Add(1)
			go proxy.TCPReverseProxy(&wg, &server, &cfg, tcpListener)
		}
	}

	wg.Wait()
}

func setupLogging() {
	stdlog.SetOutput(io.Discard)

	log.SetStyles(&log.Styles{
		Timestamp: lipgloss.NewStyle().Faint(true),
		Key:       lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(6)),
		Separator: lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(6)).Faint(true),
		Prefix:    lipgloss.NewStyle().Italic(true),

		Levels: map[log.Level]lipgloss.Style{
			log.DebugLevel: lipgloss.NewStyle().
				SetString(strings.ToUpper(log.DebugLevel.String())).
				Foreground(lipgloss.ANSIColor(6)),
			log.InfoLevel: lipgloss.NewStyle().
				SetString(strings.ToUpper(log.InfoLevel.String())).
				Foreground(lipgloss.ANSIColor(4)),
			log.WarnLevel: lipgloss.NewStyle().
				SetString(strings.ToUpper(log.WarnLevel.String())).
				Foreground(lipgloss.ANSIColor(3)),
			log.ErrorLevel: lipgloss.NewStyle().
				SetString(strings.ToUpper(log.ErrorLevel.String())).
				Bold(true).
				Foreground(lipgloss.ANSIColor(1)),
			log.FatalLevel: lipgloss.NewStyle().
				SetString(strings.ToUpper(log.FatalLevel.String())).
				Bold(true).
				Foreground(lipgloss.ANSIColor(1)),
		},
	})

	resolvedLogLevel := *logLevel
	if resolvedLogLevel == "" {
		resolvedLogLevel = os.Getenv("POLYSCALE_LOG")
	}

	if resolvedLogLevel != "" {
		lvl, err := log.ParseLevel(resolvedLogLevel)
		if err != nil {
			log.Fatal(err)
		}

		log.SetLevel(lvl)
	}
}
