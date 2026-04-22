package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/ryanccn/polyscale/config"
)

type privateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

type tlsAlgoType int

const (
	tlsAlgoTypeECDSA tlsAlgoType = iota
	tlsAlgoTypeRSA
)

func (typ *tlsAlgoType) String() string {
	switch *typ {
	case tlsAlgoTypeECDSA:
		return "ecdsa"
	case tlsAlgoTypeRSA:
		return "rsa"
	}

	log.Fatalf("unexpected generic cache type: %d", typ)
	return ""
}

type caCache struct {
	rw           sync.RWMutex
	cert         *x509.Certificate
	privKey      privateKey
	doNotRefresh bool
}

type certCache struct {
	typ   tlsAlgoType
	rw    sync.RWMutex
	cache map[string]*tls.Certificate
}

var certSubject pkix.Name

var globalCACache *caCache

var ecdsaCertCache *certCache
var rsaCertCache *certCache

func init() {
	certSubject = pkix.Name{
		Organization: []string{"Polyscale Internal CA"},
		Country:      []string{"IS"},
		Province:     []string{"Reykjavík"},
	}

	globalCACache = &caCache{
		rw:           sync.RWMutex{},
		cert:         nil,
		privKey:      nil,
		doNotRefresh: false,
	}

	ecdsaCertCache = &certCache{
		typ:   tlsAlgoTypeECDSA,
		rw:    sync.RWMutex{},
		cache: make(map[string]*tls.Certificate),
	}

	rsaCertCache = &certCache{
		typ:   tlsAlgoTypeRSA,
		rw:    sync.RWMutex{},
		cache: make(map[string]*tls.Certificate),
	}
}

func createCertAuthority() (*x509.Certificate, []byte, privateKey, error) {
	cert := &x509.Certificate{
		Subject: certSubject,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),

		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	log.Info(
		"issuing new certificate authority",
		"subject", cert.Subject.String(),
		"notBefore", cert.NotBefore.UTC().Format(time.RFC3339),
		"notAfter", cert.NotAfter.UTC().Format(time.RFC3339),
	)

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, certBytes, certPrivKey, nil
}

func getCertAuthority(cfg *config.Config) (*x509.Certificate, privateKey, error) {
	globalCACache.rw.RLock()
	if globalCACache.cert != nil && globalCACache.privKey != nil && (globalCACache.doNotRefresh || globalCACache.cert.NotAfter.After(time.Now())) {
		cert, privKey := globalCACache.cert, globalCACache.privKey
		globalCACache.rw.RUnlock()
		return cert, privKey, nil
	}
	globalCACache.rw.RUnlock()

	globalCACache.rw.Lock()
	defer globalCACache.rw.Unlock()

	if cfg.CertificateAuthority != (config.ConfigCA{}) {
		caCertBlock, _ := pem.Decode([]byte(cfg.CertificateAuthority.Cert))
		if caCertBlock == nil {
			return nil, nil, errors.New("could not decode CA certificate")
		}

		caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}

		caPrivKeyBlock, _ := pem.Decode([]byte(cfg.CertificateAuthority.Key))
		if caPrivKeyBlock == nil {
			return nil, nil, errors.New("could not decode CA private key")
		}

		caPrivKey, err := x509.ParsePKCS8PrivateKey(caPrivKeyBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}

		log.Info(
			"using certificate authority specified in config",
			"subject", caCert.Subject.String(),
			"notBefore", caCert.NotBefore.UTC().Format(time.RFC3339),
			"notAfter", caCert.NotAfter.UTC().Format(time.RFC3339),
		)

		if caCert.NotAfter.Before(time.Now()) {
			log.Warn("CA specified in config appears to be expired but will still be used")
		}

		globalCACache.cert = caCert
		globalCACache.privKey = caPrivKey.(privateKey)
		globalCACache.doNotRefresh = true

		return caCert, caPrivKey.(privateKey), nil
	}

	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return nil, nil, err
	}

	certsDir := path.Join(userConfigDir, "polyscale", "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return nil, nil, err
	}

	if caCertPEM, err := os.ReadFile(path.Join(certsDir, "ca.pem")); err == nil {
		if caCertBlock, _ := pem.Decode(caCertPEM); caCertBlock != nil {
			if caCert, err := x509.ParseCertificate(caCertBlock.Bytes); err == nil && caCert.NotAfter.After(time.Now()) {
				if caPrivKeyPEM, err := os.ReadFile(path.Join(certsDir, "ca.key")); err == nil {
					if caPrivKeyBlock, _ := pem.Decode(caPrivKeyPEM); caPrivKeyBlock != nil {
						if caPrivKey, err := x509.ParsePKCS8PrivateKey(caPrivKeyBlock.Bytes); err == nil {
							caPrivKey := caPrivKey.(privateKey)
							globalCACache.cert = caCert
							globalCACache.privKey = caPrivKey
							return caCert, caPrivKey, nil
						}
					}
				}
			}
		}
	}

	caCert, caCertBytes, caPrivKey, err := createCertAuthority()
	if err != nil {
		return nil, nil, err
	}

	caCertPEM := new(bytes.Buffer)
	pem.Encode(caCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	})

	caPrivKeyDER, err := x509.MarshalPKCS8PrivateKey(caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: caPrivKeyDER,
	})

	if err := os.WriteFile(path.Join(certsDir, "ca.pem"), caCertPEM.Bytes(), 0700); err != nil {
		return nil, nil, err
	}

	if err := os.WriteFile(path.Join(certsDir, "ca.key"), caPrivKeyPEM.Bytes(), 0700); err != nil {
		return nil, nil, err
	}

	globalCACache.cert = caCert
	globalCACache.privKey = caPrivKey

	return caCert, caPrivKey, nil
}

func createCertificate(cfg *config.Config, typ tlsAlgoType, sni string) (*x509.Certificate, []byte, crypto.PrivateKey, error) {
	cert := &x509.Certificate{
		Subject:  certSubject,
		DNSNames: []string{sni},

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	log.Info(
		"issuing new TLS certificate",
		"type", typ.String(),
		"subject", cert.Subject.String(),
		"dnsNames", cert.DNSNames,
		"notBefore", cert.NotBefore.UTC().Format(time.RFC3339),
		"notAfter", cert.NotAfter.UTC().Format(time.RFC3339),
	)

	switch typ {
	case tlsAlgoTypeECDSA:
		certPrivKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}

		caCert, caPrivKey, err := getCertAuthority(cfg)
		if err != nil {
			return nil, nil, nil, err
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivKey)
		if err != nil {
			return nil, nil, nil, err
		}

		return cert, certBytes, certPrivKey, nil

	case tlsAlgoTypeRSA:
		certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, nil, err
		}

		caCert, caPrivKey, err := getCertAuthority(cfg)
		if err != nil {
			return nil, nil, nil, err
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivKey)
		if err != nil {
			return nil, nil, nil, err
		}

		return cert, certBytes, certPrivKey, nil
	}

	return nil, nil, nil, fmt.Errorf("unsupported TLS type: %v", typ)
}

func GetCertificate(cfg *config.Config) func(tlsInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(tlsInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
		sni := tlsInfo.ServerName

		if sni == "" {
			return nil, errors.New("empty SNI provided :(")
		}

		tlsSupportsError := error(nil)

		for _, certCache := range []*certCache{ecdsaCertCache, rsaCertCache} {
			certCache.rw.RLock()
			if certCache.cache[sni] != nil && certCache.cache[sni].Leaf.NotAfter.After(time.Now()) {
				tlsCert := certCache.cache[sni]
				certCache.rw.RUnlock()

				if err := tlsInfo.SupportsCertificate(tlsCert); err == nil {
					return tlsCert, nil
				}
			}
			certCache.rw.RUnlock()

			tlsCert, err := (func() (*tls.Certificate, error) {
				certCache.rw.Lock()
				defer certCache.rw.Unlock()

				cert, certBytes, certPrivKey, err := createCertificate(cfg, certCache.typ, sni)
				if err != nil {
					return nil, err
				}

				tlsCert := &tls.Certificate{
					Certificate: [][]byte{certBytes},
					PrivateKey:  certPrivKey,
					Leaf:        cert,
				}

				certCache.cache[sni] = tlsCert
				return tlsCert, nil
			})()

			if err != nil {
				return nil, err
			}

			if err := tlsInfo.SupportsCertificate(tlsCert); err == nil {
				return tlsCert, nil
			} else {
				tlsSupportsError = err
			}
		}

		if tlsSupportsError != nil {
			return nil, tlsSupportsError
		} else {
			return nil, errors.New("unknown error in TLS certificate issuance")
		}
	}
}
