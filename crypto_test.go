package stcp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

func TestAESGCMBasic(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("NewGCM failed: %v", err)
	}

	plaintext := []byte("hello world")
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	out, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(out, plaintext) {
		t.Errorf("decrypted text mismatch: got %s, want %s", out, plaintext)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	c := &Conn{}
	key := make([]byte, 32)
	rand.Read(key)

	if err := c.initAESGCMKey(key); err != nil {
		t.Fatalf("initAESGCMKey failed: %v", err)
	}

	plaintext := []byte("test message for encryption")
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text mismatch")
	}
}

func TestEncryptProducesDifferentOutput(t *testing.T) {
	c := &Conn{}
	key := make([]byte, 32)
	rand.Read(key)
	c.initAESGCMKey(key)

	plaintext := []byte("same message")

	ct1, _ := c.Encrypt(plaintext)
	ct2, _ := c.Encrypt(plaintext)

	if bytes.Equal(ct1, ct2) {
		t.Error("Encrypt should produce different output due to random nonce")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	c1 := &Conn{}
	c2 := &Conn{}

	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	c1.initAESGCMKey(key1)
	c2.initAESGCMKey(key2)

	ciphertext, err := c1.Encrypt([]byte("test"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = c2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt should fail with wrong key")
	}
}

func TestDecryptWithTamperedCiphertext(t *testing.T) {
	c := &Conn{}
	key := make([]byte, 32)
	rand.Read(key)
	c.initAESGCMKey(key)

	ciphertext, err := c.Encrypt([]byte("test"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = c.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt should fail with tampered ciphertext")
	}
}

func TestDecryptShortCiphertext(t *testing.T) {
	c := &Conn{}
	key := make([]byte, 32)
	rand.Read(key)
	c.initAESGCMKey(key)

	_, err := c.Decrypt([]byte("short"))
	if err != ErrCipherTooShort {
		t.Errorf("expected ErrCipherTooShort, got %v", err)
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	c := &Conn{}
	key := make([]byte, 32)
	rand.Read(key)
	c.initAESGCMKey(key)

	ciphertext, err := c.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty decrypted text")
	}
}

func TestEncryptLargePlaintext(t *testing.T) {
	c := &Conn{}
	key := make([]byte, 32)
	rand.Read(key)
	c.initAESGCMKey(key)

	plaintext := make([]byte, 1024*1024)
	rand.Read(plaintext)

	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted text mismatch for large plaintext")
	}
}

func TestNonceSize(t *testing.T) {
	c := &Conn{}
	key := make([]byte, 32)
	rand.Read(key)
	c.initAESGCMKey(key)

	nonceSize := c.aesgcm.NonceSize()
	if nonceSize != 12 {
		t.Errorf("expected NonceSize 12, got %d", nonceSize)
	}
}

func TestOverhead(t *testing.T) {
	c := &Conn{}
	key := make([]byte, 32)
	rand.Read(key)
	c.initAESGCMKey(key)

	overhead := c.aesgcm.Overhead()
	if overhead != 16 {
		t.Errorf("expected Overhead 16, got %d", overhead)
	}
}
