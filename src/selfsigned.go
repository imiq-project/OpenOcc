package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func generateSelfSignedCert(hostname string, dir string) error {
	certFile := dir + "/server.crt"
	keyFile := dir + "/server.key"

	log.Println("🔏 Generating new self-signed TLS certificate...")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Save certificate
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()

	// Save private key
	keyOut, _ := os.Create(keyFile)
	b, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	keyOut.Close()

	log.Printf("✅ Saved cert: %s and key: %s\n", certFile, keyFile)
	return nil
}

func createOrLoadCertificates(hostname string, dir string) (tls.Certificate, error) {
	// TODO: duplicated
	certFile := dir + "/server.crt"
	keyFile := dir + "/server.key"

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		if err := generateSelfSignedCert(hostname, dir); err != nil {
			log.Fatalf("failed to generate cert: %v", err)
		}
	}
	// TODO: check that hostname of certs matches the given one
	return tls.LoadX509KeyPair(certFile, keyFile)
}
