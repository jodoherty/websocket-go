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

type keyCert struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func main() {
	dir := flag.String("dir", "e2e/certs", "output directory")
	flag.Parse()

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatal(err)
	}

	ca := mustCA()
	server := mustLeaf(ca, x509.ExtKeyUsageServerAuth, "localhost",
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	client := mustLeaf(ca, x509.ExtKeyUsageClientAuth, "e2e-client", nil, nil)

	if err := writeCert(*dir, "ca.pem", ca.cert); err != nil {
		log.Fatal(err)
	}
	if err := writeCert(*dir, "server.pem", server.cert); err != nil {
		log.Fatal(err)
	}
	if err := writeKey(*dir, "server.key", server.key); err != nil {
		log.Fatal(err)
	}
	if err := writeCert(*dir, "client.pem", client.cert); err != nil {
		log.Fatal(err)
	}
	if err := writeKey(*dir, "client.key", client.key); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("certificates written to %s\n", *dir)
}

func mustCA() keyCert {
	key, cert := newCert(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ws-e2e CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}, nil)
	return keyCert{key: key, cert: cert}
}

func mustLeaf(ca keyCert, ext x509.ExtKeyUsage, cn string, dns []string, ips []net.IP) keyCert {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatal(err)
	}
	key, cert := newCert(&x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{ext},
		DNSNames:     dns,
		IPAddresses:  ips,
	}, &ca)
	return keyCert{key: key, cert: cert}
}

func newCert(tmpl *x509.Certificate, parent *keyCert) (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
	return os.WriteFile(filepath.Join(dir, name),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644)
}

func writeKey(dir, name string, key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}
