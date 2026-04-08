package stcp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

var NowTime = time.Now

func NowMs() int64 {
	return time.Now().UnixMilli()
}

func LoadPemCertficate(file string) (*x509.Certificate, error) {
	data, err := ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func LoadPemCertKey(file string) (crypto.PrivateKey, error) {
	data, err := ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func Sign(privateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, data)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, data)
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func VerifySignature(pubKey crypto.PublicKey, data, sign []byte) bool {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, data, sign) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(key, data, sign)
	default:
		return false
	}
}

func ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func DeriveKey(ecdhKey, clientNonce, serverNonce []byte) []byte {
	h := sha256.New()
	h.Write(ecdhKey)
	h.Write(clientNonce)
	h.Write(serverNonce)
	return h.Sum(nil)
}

func GenerateSelfSignedCert(commonName string, notBefore, notAfter time.Time) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}
