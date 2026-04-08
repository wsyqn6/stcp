package stcp

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func BenchmarkConnWriteRead(b *testing.B) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		b.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKeyForBench(certPEM, keyPEM)
	if err != nil {
		b.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		b.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer lis.Close()

	serverConnCh := make(chan net.Conn, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		serverConnCh <- conn
	}()

	clientConn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		b.Fatalf("Dial failed: %v", err)
	}
	defer clientConn.Close()

	serverConn := <-serverConnCh
	if serverConn == nil {
		b.Fatal("Accept failed")
	}
	defer serverConn.Close()

	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := clientConn.Write(data)
		if err != nil {
			b.Fatalf("Write failed: %v", err)
		}

		buf := make([]byte, 1024)
		_, err = serverConn.Read(buf)
		if err != nil {
			b.Fatalf("Read failed: %v", err)
		}
	}
}

func BenchmarkConnParallel(b *testing.B) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		b.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKeyForBench(certPEM, keyPEM)
	if err != nil {
		b.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		b.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer lis.Close()

	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
		if err != nil {
			b.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		for pb.Next() {
			conn.Write(data)
			buf := make([]byte, 256)
			conn.Read(buf)
		}
	})
}

func parseCertAndKeyForBench(certPEM, keyPEM []byte) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, nil
	}
	return cert, keyBlock.Bytes, nil
}
