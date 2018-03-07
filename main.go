package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"flag"
)

var (
	certificateFilename   = flag.String("cert", "", "Certificate filename")
	caPrivateKeyFilename  = flag.String("certpriv", "", "CA private key filename")
	caCertificateFilename = flag.String("ca", "", "CA certificate filename")
	outputFilename        = flag.String("out", "", "Output filename")
)

func main() {
	flag.Parse()

	templateCert, err := parseCertificate(*certificateFilename)
	if err != nil {
		panic(err)
	}

	templateCert.NotAfter = templateCert.NotAfter.AddDate(2, 0, 0)

	caCert, err := parseCertificate(*caCertificateFilename)
	if err != nil {
		panic(err)
	}

	privateKey, err := parsePrivateKey(*caPrivateKeyFilename)
	if err != nil {
		panic(err)
	}

	publicKey := templateCert.PublicKey

	certBytes, err := x509.CreateCertificate(rand.Reader, templateCert, caCert, publicKey, privateKey)
	if err != nil {
		panic(err)
	}

	outputPEMCert := encodeCertPEM(certBytes)

	if *outputFilename != "" {
		ioutil.WriteFile(*outputFilename, outputPEMCert, 0755)
	} else {
		fmt.Println(string(outputPEMCert))
	}
}

func parseCertificate(filename string) (*x509.Certificate, error) {
	c, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(c))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

func parsePublicKey(filename string) (*rsa.PublicKey, error) {
	c, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(c))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func parsePrivateKey(filename string) (*rsa.PrivateKey, error) {
	c, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(c))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func encodeCertPEM(raw []byte) []byte {
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: raw,
	}
	return pem.EncodeToMemory(&block)
}
