package stcp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

func TestLoadPemCertficate(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	tmpDir := t.TempDir()
	certFile := tmpDir + "/cert.pem"
	keyFile := tmpDir + "/key.pem"

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cert, err := LoadPemCertficate(certFile)
	if err != nil {
		t.Fatalf("LoadPemCertficate failed: %v", err)
	}

	if cert.Subject.CommonName != "test" {
		t.Errorf("expected CommonName 'test', got '%s'", cert.Subject.CommonName)
	}
}

func TestLoadPemCertKey(t *testing.T) {
	_, keyPEM, err := GenerateSelfSignedCert("test", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	tmpDir := t.TempDir()
	keyFile := tmpDir + "/key.pem"

	if err := os.WriteFile(keyFile, keyPEM, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	key, err := LoadPemCertKey(keyFile)
	if err != nil {
		t.Fatalf("LoadPemCertKey failed: %v", err)
	}

	_, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", key)
	}
}

func TestSignAndVerify(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	data := []byte("test message")
	sig, err := Sign(privKey, data)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok := VerifySignature(&privKey.PublicKey, data, sig)
	if !ok {
		t.Error("VerifySignature failed")
	}

	ok = VerifySignature(&privKey.PublicKey, []byte("wrong data"), sig)
	if ok {
		t.Error("VerifySignature should fail for wrong data")
	}
}

func TestDeriveKey(t *testing.T) {
	ecdhKey := make([]byte, 32)
	clientNonce := make([]byte, 32)
	serverNonce := make([]byte, 32)

	rand.Read(ecdhKey)
	rand.Read(clientNonce)
	rand.Read(serverNonce)

	key1 := DeriveKey(ecdhKey, clientNonce, serverNonce)
	if len(key1) != 32 {
		t.Errorf("expected key length 32, got %d", len(key1))
	}

	key2 := DeriveKey(ecdhKey, clientNonce, serverNonce)
	if string(key1) != string(key2) {
		t.Error("DeriveKey should produce same output for same input")
	}

	otherNonce := make([]byte, 32)
	otherNonce[0] = 1
	key3 := DeriveKey(ecdhKey, clientNonce, otherNonce)
	if string(key1) == string(key3) {
		t.Error("DeriveKey should produce different output for different nonce")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("certPEM is empty")
	}

	if len(keyPEM) == 0 {
		t.Error("keyPEM is empty")
	}
}

func TestReadFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := tmpDir + "/test.txt"
	content := []byte("test content")

	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	data, err := ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(data) != string(content) {
		t.Errorf("expected '%s', got '%s'", content, data)
	}
}

func TestReadFileNotFound(t *testing.T) {
	_, err := ReadFile("/nonexistent/file")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
