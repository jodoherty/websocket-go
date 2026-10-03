// Command certgen generates the throwaway certificates the demo server and
// the e2e suite use: a CA, a server certificate (SAN: 127.0.0.1/localhost),
// and a client certificate for mTLS.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	// keyBits is the RSA key size. 2048 is the current minimum considered
	// safe for signatures (RFC 8017 §5.6 / NIST).
	keyBits = 2048
	// serialBits is the width of a random leaf serial number.
	serialBits = 128
	// caValidity and leafValidity are the certificate lifetimes.
	caValidity   = 2 * 365 * 24 * time.Hour
	leafValidity = 365 * 24 * time.Hour
	// backdate gives the certs an hour of clock-skew headroom.
	backdate = time.Hour
	// certFilePerm and keyFilePerm are the on-disk modes. The key is
	// owner-only; the cert is world-readable.
	certFilePerm = 0o644
	keyFilePerm  = 0o600
	// dirPerm is the mode for the output directory.
	dirPerm = 0o750
)

type keyCert struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func main() {
	dir := flag.String("dir", "e2e/certs", "output directory")
	flag.Parse()

	mkdirErr := os.MkdirAll(*dir, dirPerm)
	if mkdirErr != nil {
		log.Fatal(mkdirErr)
	}

	rootCA := mustCA()
	server := mustLeaf(rootCA, x509.ExtKeyUsageServerAuth, "localhost",
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	client := mustLeaf(rootCA, x509.ExtKeyUsageClientAuth, "e2e-client", nil, nil)

	writes := []struct {
		name string
		err  error
	}{
		{"ca.pem", writeCert(*dir, "ca.pem", rootCA.cert)},
		{"server.pem", writeCert(*dir, "server.pem", server.cert)},
		{"server.key", writeKey(*dir, "server.key", server.key)},
		{"client.pem", writeCert(*dir, "client.pem", client.cert)},
		{"client.key", writeKey(*dir, "client.key", client.key)},
	}
	for _, write := range writes {
		if write.err != nil {
			log.Fatalf("write %s: %v", write.name, write.err)
		}
	}
	log.Printf("certificates written to %s", *dir)
}

func mustCA() keyCert {
	key, cert := newCert(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ws-e2e CA"},
		NotBefore:             time.Now().Add(-backdate),
		NotAfter:              time.Now().Add(caValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, nil)

	return keyCert{key: key, cert: cert}
}

func mustLeaf(issuer keyCert, ext x509.ExtKeyUsage, commonName string, dns []string, ips []net.IP) keyCert {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialBits))
	if err != nil {
		log.Fatal(err)
	}
	key, cert := newCert(&x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-backdate),
		NotAfter:     time.Now().Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{ext},
		DNSNames:     dns,
		IPAddresses:  ips,
	}, &issuer)

	return keyCert{key: key, cert: cert}
}

func newCert(tmpl *x509.Certificate, parent *keyCert) (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		log.Fatal(err)
	}
	var parentCert *x509.Certificate
	var parentKey any
	if parent == nil {
		parentCert, parentKey = tmpl, key
	} else {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}

	return key, cert
}

func writeCert(dir, name string, cert *x509.Certificate) error {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	writeErr := os.WriteFile(filepath.Join(dir, name), block, certFilePerm)
	if writeErr != nil {
		return fmt.Errorf("certgen: write %q: %w", name, writeErr)
	}

	return nil
}

func writeKey(dir, name string, key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("certgen: marshal key %q: %w", name, err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	writeErr := os.WriteFile(filepath.Join(dir, name), block, keyFilePerm)
	if writeErr != nil {
		return fmt.Errorf("certgen: write %q: %w", name, writeErr)
	}

	return nil
}
