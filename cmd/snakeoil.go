package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	keyPath            = kingpin.Flag("key", "RSA private key").Required().String()
	wednesdayExpiry    = kingpin.Flag("wednesday-expiry", "Round the expiry to the nearest Wednesday lunchtime").Default("false").Bool()
	commonName         = kingpin.Flag("CN", "The fully qualified domain name used for DNS lookups of your server").String()
	organization       = kingpin.Flag("O", "Name of organization").Strings()
	organizationalUnit = kingpin.Flag("OU", "Division or department in organization").Strings()
	country            = kingpin.Flag("C", "Two letter country code").Strings()
	province           = kingpin.Flag("ST", "State, province or county").Strings()
	locality           = kingpin.Flag("L", "City").Strings()
	expiry             = kingpin.Flag("expires", "Expiry").Default("8760h").Duration()
	dnsNames           = kingpin.Flag("dns", "DNS names").Strings()
	ipAddresses        = kingpin.Flag("ip", "Address to add to the SAN").IPList()
	interfaces         = kingpin.Flag("interface", "Interface to scan for addresses").Strings()
	certPath           = kingpin.Arg("PATH", "Path to write certificate to").Required().String()
)

const caCommonName string = "github.com/simon-engledew/snakeoil"

func useExisting() bool {
	data, err := ioutil.ReadFile(*certPath)
	if err != nil {
		return false
	}

	certDERBlock, _ := pem.Decode(data)
	if certDERBlock == nil {
		return true
	}

	if certDERBlock.Type != "CERTIFICATE" {
		return true
	}

	cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return true
	}

	if cert.Issuer.CommonName != caCommonName {
		return true
	}

	now := time.Now()

	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false
	}

	for _, addr := range *ipAddresses {
		if cert.VerifyHostname(addr.String()) != nil {
			return false
		}
	}

	for _, dnsName := range *dnsNames {
		if cert.VerifyHostname(dnsName) != nil {
			return false
		}
	}

	if cert.Subject.CommonName != *commonName {
		return false
	}

	return true
}

func getAddresses(names ...string) []net.IP {
	var addresses []net.IP

	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			panic(err)
		}

		addrs, err := iface.Addrs()
		if err != nil {
			panic(err)
		}

		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					addresses = append(addresses, ipnet.IP)
				}
			}
		}
	}

	return addresses
}

func resolveAddr(addr string) []string {
	var result []string

	found, _ := net.LookupAddr(addr)

	for _, name := range found {
		host := strings.TrimSuffix(name, ".")

		result = append(result, host)

		cname, err := net.LookupCNAME(host)
		if err == nil && cname != name {
			result = append(result, strings.TrimSuffix(cname, "."))
		}
	}

	return result
}

func main() {
	kingpin.Parse()

	if _, err := os.Stat(*keyPath); os.IsNotExist(err) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)

		if err != nil {
			panic(err)
		}

		err = ioutil.WriteFile(
			*keyPath,
			pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
			}),
			0600,
		)

		if err != nil {
			panic(err)
		}
	}

	key, err := ioutil.ReadFile(*keyPath)
	if err != nil {
		panic(err)
	}

	keyDERBlock, _ := pem.Decode(key)

	priv, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		panic(err)
	}

	if len(*interfaces) > 0 {
		*ipAddresses = append(*ipAddresses, getAddresses(*interfaces...)...)
	}

	for _, addr := range *ipAddresses {
		*dnsNames = append(*dnsNames, resolveAddr(addr.String())...)
	}

	if *commonName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatal(err)
		}
		commonName = &hostname
	}

	if useExisting() {
		os.Exit(1)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	parentSerialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	notBefore := time.Now().UTC()
	notAfter := notBefore.Add(*expiry).UTC()

	if *wednesdayExpiry {
		daysToWednesday := time.Wednesday - notAfter.Weekday()
		if daysToWednesday < 0 {
			daysToWednesday += 7
		}
		notAfter = notAfter.Add(time.Duration(daysToWednesday) * time.Hour * 24)
		notAfter = time.Date(
			notAfter.Year(),
			notAfter.Month(),
			notAfter.Day(),
			11,
			0,
			0,
			0,
			notAfter.Location(),
		)
	}

	issuer := x509.Certificate{
		SerialNumber: parentSerialNumber,
		Subject: pkix.Name{
			CommonName:         caCommonName,
			Country:            []string{},
			Organization:       []string{},
			OrganizationalUnit: []string{},
			Locality:           []string{},
			Province:           []string{},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         *commonName,
			Country:            *country,
			Organization:       *organization,
			OrganizationalUnit: *organizationalUnit,
			Locality:           *locality,
			Province:           *province,
		},
		Issuer: pkix.Name{
			CommonName:         *commonName,
			Country:            *country,
			Organization:       *organization,
			OrganizationalUnit: *organizationalUnit,
			Locality:           *locality,
			Province:           *province,
		},

		IPAddresses: *ipAddresses,
		DNSNames:    *dnsNames,

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &issuer, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}

	ioutil.WriteFile(
		*certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}),
		0644,
	)
}
