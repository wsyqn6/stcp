package stcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var bodyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, MaxBodySize)
		return &b
	},
}

type Conn struct {
	net.Conn
	key           []byte
	aesgcm        cipher.AEAD
	kid           uint64
	clientNonce   [NonceLength]byte
	serverNonce   [NonceLength]byte
	rMu           sync.Mutex
	wMu           sync.Mutex
	readDeadline  atomic.Pointer[time.Time]
	writeDeadline atomic.Pointer[time.Time]
}

func (c *Conn) initAESGCMKey(key []byte) error {
	if c.aesgcm != nil {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	c.aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) Encrypt(plaintext []byte) ([]byte, error) {
	if c.aesgcm == nil {
		return nil, ErrAESGCMNotInit
	}
	nonceSize := c.aesgcm.NonceSize()
	nonce := make([]byte, nonceSize, nonceSize+len(plaintext)+c.aesgcm.Overhead())
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := c.aesgcm.Seal(nonce[nonceSize:nonceSize], nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func (c *Conn) Decrypt(ciphertext []byte) ([]byte, error) {
	if c.aesgcm == nil {
		return nil, ErrAESGCMNotInit
	}
	nonceSize := c.aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCipherTooShort
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := c.aesgcm.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if len(b) < HeaderLength {
		return 0, io.ErrShortBuffer
	}

	deadline := c.readDeadline.Load()
	if deadline != nil && time.Now().After(*deadline) {
		return 0, io.EOF
	}

	var header Header
	_, err = io.ReadFull(c.Conn, header[:])
	if err != nil {
		return 0, err
	}

	if header.Type() != HeaderTypeCryptoData {
		return 0, ErrUnexpectedPrefix
	}

	bodyLen := header.ContentLength()
	if bodyLen == 0 {
		return 0, ErrEmptyBody
	}
	if bodyLen > MaxBodySize {
		return 0, ErrPacketTooLarge
	}

	cipherBody := make([]byte, bodyLen)
	_, err = io.ReadFull(c.Conn, cipherBody)
	if err != nil {
		return 0, err
	}

	data, err := c.Decrypt(cipherBody)
	if err != nil {
		return 0, err
	}

	copy(b, data)
	return len(data), nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	deadline := c.writeDeadline.Load()
	if deadline != nil && time.Now().After(*deadline) {
		return 0, io.EOF
	}

	c.wMu.Lock()
	defer c.wMu.Unlock()

	cipherData, err := c.Encrypt(b)
	if err != nil {
		return 0, err
	}

	header := newHeader(HeaderTypeCryptoData, HeaderStatusSuccess, uint32(len(cipherData)))
	_, err = c.Conn.Write(header[:])
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(cipherData)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadline.Store(nil)
	} else {
		c.readDeadline.Store(&t)
	}
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.writeDeadline.Store(nil)
	} else {
		c.writeDeadline.Store(&t)
	}
	return nil
}

func (c *Conn) handshake(conn net.Conn, isServer bool, cert *x509.Certificate, privateKey any, rootCert *x509.Certificate) error {
	if isServer {
		return c.serverHandshake(conn, cert, privateKey)
	}
	return c.clientHandshake(conn, cert, rootCert)
}

func (c *Conn) serverHandshake(conn net.Conn, cert *x509.Certificate, privateKey any) error {
	header, err := ReadHeader(conn)
	if err != nil {
		return err
	}
	if header.Type() != HeaderTypeCryptoHandshake {
		return ErrUnexpectedPrefix
	}
	if header.Status() != HeaderStatusSuccess {
		return ErrFailResponse
	}

	body, err := header.ReadBody(conn)
	if err != nil {
		return err
	}

	spiderBytes := body[:len(Stcp)]
	for i := range spiderBytes {
		if spiderBytes[i] != Stcp[i] {
			return ErrUnexpectedPrefix
		}
	}

	publicKey := body[len(Stcp) : len(Stcp)+ECDHKeyLength]
	c.clientNonce = [NonceLength]byte{}
	copy(c.clientNonce[:], body[len(Stcp)+ECDHKeyLength:])

	_, err = rand.Read(c.serverNonce[:])
	if err != nil {
		return err
	}

	curve := ecdh.X25519()
	selfPrivKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	pubK, err := curve.NewPublicKey(publicKey)
	if err != nil {
		return err
	}

	shareKey, err := selfPrivKey.ECDH(pubK)
	if err != nil {
		return err
	}
	c.key = shareKey
	c.kid = uint64(len(c.key))

	selfPubKey := selfPrivKey.PublicKey().Bytes()

	sign, err := Sign(privateKey, selfPubKey)
	if err != nil {
		return err
	}

	certLen := len(cert.Raw)
	signLen := len(sign)
	respBody := make([]byte, 2+certLen+ECDHKeyLength+signLen+NonceLength+8)
	binary.BigEndian.PutUint16(respBody, uint16(certLen))
	copy(respBody[2:], cert.Raw)
	copy(respBody[2+certLen:], selfPubKey)
	copy(respBody[2+certLen+ECDHKeyLength:], sign)
	copy(respBody[2+certLen+ECDHKeyLength+signLen:], c.serverNonce[:])
	binary.BigEndian.PutUint64(respBody[2+certLen+ECDHKeyLength+signLen+NonceLength:], c.kid)

	derivedKey := DeriveKey(c.key, c.clientNonce[:], c.serverNonce[:])
	if err := c.initAESGCMKey(derivedKey); err != nil {
		return err
	}

	conn.SetWriteDeadline(time.Now().Add(time.Second * 30))
	err = SendOk(conn, HeaderTypeCryptoHandshake, respBody)
	if err != nil {
		return err
	}

	return nil
}

func (c *Conn) clientHandshake(conn net.Conn, cert *x509.Certificate, rootCert *x509.Certificate) error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	if _, err := rand.Read(c.clientNonce[:]); err != nil {
		return err
	}

	body := make([]byte, len(Stcp)+ECDHKeyLength+NonceLength)
	copy(body, Stcp)
	copy(body[len(Stcp):], privateKey.PublicKey().Bytes())
	copy(body[len(Stcp)+ECDHKeyLength:], c.clientNonce[:])

	err = SendOk(conn, HeaderTypeCryptoHandshake, body)
	if err != nil {
		return err
	}

	header, err := ReadHeader(conn)
	if err != nil {
		return err
	}
	if header.Status() != HeaderStatusSuccess {
		return ErrFailResponse
	}

	resBody, err := header.ReadBody(conn)
	if err != nil {
		return err
	}

	certLen := binary.BigEndian.Uint16(resBody[:2])
	certData := resBody[2 : certLen+2]
	serverCert, err := x509.ParseCertificate(certData)
	if err != nil {
		return err
	}

	if rootCert != nil {
		pool := x509.NewCertPool()
		pool.AddCert(rootCert)
		opts := x509.VerifyOptions{Roots: pool}
		_, err = serverCert.Verify(opts)
		if err != nil {
			return err
		}
	}

	publicKey := resBody[2+certLen : 2+certLen+ECDHKeyLength]

	signStart := 2 + certLen + ECDHKeyLength
	signEnd := len(resBody) - NonceLength - 8
	sign := resBody[signStart:signEnd]

	ok := VerifySignature(serverCert.PublicKey, publicKey, sign)
	if !ok {
		return ErrFailResponse
	}

	pubK, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return err
	}
	shareKey, err := privateKey.ECDH(pubK)
	if err != nil {
		return err
	}

	kidPos := len(resBody) - 8
	copy(c.serverNonce[:], resBody[signEnd:kidPos])
	c.kid = binary.BigEndian.Uint64(resBody[kidPos:])

	derivedKey := DeriveKey(shareKey, c.clientNonce[:], c.serverNonce[:])
	if err := c.initAESGCMKey(derivedKey); err != nil {
		return err
	}

	return nil
}
