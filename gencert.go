// gencert creates server + client certificates signed with the same self-issued CA
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/artyom/autoflags"
)

func main() {
	params := struct {
		Hosts          string `flag:"hosts,comma-separated list of hostnames"`
		ClientKeyFile  string `flag:"client.key,file to save client certificate key"`
		ClientCertFile string `flag:"client.cert,file to save client certificate"`
		ServerKeyFile  string `flag:"server.key,file to save server certificate key"`
		ServerCertFile string `flag:"server.cert,file to save server certificate"`
	}{
		ClientKeyFile:  "client-key.pem",
		ClientCertFile: "client-cert.pem",
		ServerKeyFile:  "server-key.pem",
		ServerCertFile: "server-cert.pem",
	}
	autoflags.Define(&params)
	flag.Parse()
	if len(params.Hosts) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	caCert, caKey, err := generateCA()
	if err != nil {
		log.Fatal(err)
	}
	ca, err := parseCA(caCert)
	if err != nil {
		log.Fatal(err)
	}
	serverCert, serverKey, err := generateCertificate(ca, caKey, strings.Split(params.Hosts, ","))
	if err != nil {
		log.Fatal(err)
	}
	clientCert, clientKey, err := generateCertificate(ca, caKey, nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := saveCerts(params.ServerCertFile, serverCert, caCert); err != nil {
		log.Fatal(err)
	}
	if err := saveCerts(params.ClientCertFile, clientCert, caCert); err != nil {
		log.Fatal(err)
	}
	if err := saveKey(params.ServerKeyFile, serverKey); err != nil {
		log.Fatal(err)
	}
	if err := saveKey(params.ClientKeyFile, clientKey); err != nil {
		log.Fatal(err)
	}
}

func parseCA(data []byte) (*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func generateCA() ([]byte, *ecdsa.PrivateKey, error) { return generateCertificate(nil, nil, nil) }

func generateCertificate(signer *x509.Certificate, signerKey interface{}, hosts []string) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: now,
		NotAfter:  now.Add(3 * 365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	switch {
	case signer == nil: // CA
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	case len(hosts) > 0: // server cert
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, h := range hosts {
			if ip := net.ParseIP(h); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, h)
			}
		}
	default: // client cert
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if signer == nil {
		signer = &template
		signerKey = key
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, signer, &key.PublicKey, signerKey)
	return derBytes, key, err
}

func saveKey(name string, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return savePEM(name, "EC PRIVATE KEY", b)
}

func saveCerts(name string, certs ...[]byte) error {
	return savePEM(name, "CERTIFICATE", certs...)
}

func savePEM(name, header string, certs ...[]byte) error {
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, derBytes := range certs {
		if err := pem.Encode(f, &pem.Block{Type: header, Bytes: derBytes}); err != nil {
			return err
		}
	}
	return f.Close()
}

func init() { log.SetFlags(log.Lshortfile) }
