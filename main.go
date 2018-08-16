package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"time"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	key                = kingpin.Flag("key", "RSA private key").Required().String()
	commonName         = kingpin.Flag("CN", "The fully qualified domain name used for DNS lookups of your server").String()
	organization       = kingpin.Flag("O", "Name of organization").Strings()
	organizationalUnit = kingpin.Flag("OU", "Division or department in organization").Strings()
	country            = kingpin.Flag("C", "Two letter country code").Strings()
	province           = kingpin.Flag("ST", "State, province or county").Strings()
	locality           = kingpin.Flag("L", "City").Strings()
	expiry             = kingpin.Flag("expires", "Expiry").Default("8760h").Duration()
)

func GetAddresses() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		panic("No available adaptors")
	}

	var addresses []net.IP

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				addresses = append(addresses, ipnet.IP)
			}
		}
	}

	return addresses
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	kingpin.Parse()

	key, err := ioutil.ReadFile(*key)
	if err != nil {
		log.Fatal(err)
	}

	keyDERBlock, _ := pem.Decode(key)

	priv, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	addresses := GetAddresses()

	if *commonName == "" {
		primaryAddress := addresses[len(addresses)-1].String()
		commonName = &primaryAddress
	}

	b := make([]byte, 128)
	_, err = rand.Read(b)

	if err != nil {
		log.Fatal(err)
	}

	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(b)

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

		IPAddresses: addresses,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(*expiry),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	fmt.Printf(out.String())
	out.Reset()
	pem.Encode(out, keyDERBlock)
	fmt.Printf(out.String())
}
