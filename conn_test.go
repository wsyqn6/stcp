package stcp

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func parseCertAndKey(certPEM, keyPEM []byte) (*x509.Certificate, []byte, error) {
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

func TestServerClient(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer lis.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write([]byte("echo: " + string(buf[:n])))
	}()

	conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	testMsg := []byte("hello")
	_, err = conn.Write(testMsg)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	expected := "echo: hello"
	if string(buf[:n]) != expected {
		t.Errorf("got %q, want %q", string(buf[:n]), expected)
	}

	lis.Close()
	wg.Wait()
}

func TestConcurrentReadWrite(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer lis.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			conn.Write(buf[:n])
		}
	}()

	conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	var writeWg sync.WaitGroup
	for i := 0; i < 5; i++ {
		writeWg.Add(1)
		go func(idx int) {
			defer writeWg.Done()
			msg := strings.Repeat(string(rune('a'+idx)), 10)
			conn.Write([]byte(msg))
		}(i)
	}

	writeWg.Wait()
	conn.Close()
	lis.Close()
	wg.Wait()
}

func TestClose(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	serverConnCh := make(chan net.Conn)
	go func() {
		conn, err := lis.Accept()
		if err == nil {
			serverConnCh <- conn
		}
	}()

	conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	serverConn := <-serverConnCh

	err = conn.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	buf := make([]byte, 1)
	_, err = serverConn.Read(buf)
	if err == nil {
		t.Error("server should detect close")
	}

	lis.Close()
}

func TestDeadline(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer lis.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(time.Second)
	}()

	conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(100 * time.Millisecond)
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected timeout error")
	}

	lis.Close()
	wg.Wait()
}

func TestLocalAddr(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer lis.Close()

	conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}

	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}
}

func TestMultipleWriteRead(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer lis.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		for i := 0; i < 3; i++ {
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	}()

	conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	for i := 0; i < 3; i++ {
		msg := []byte("message " + string(rune('0'+i)))
		conn.Write(msg)

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		if string(buf[:n]) != string(msg) {
			t.Errorf("got %q, want %q", string(buf[:n]), string(msg))
		}
	}

	lis.Close()
	wg.Wait()
}

func TestServerClose(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	err = lis.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, err = lis.Accept()
	if err == nil {
		t.Error("Accept should fail after close")
	}
}

var _ io.ReadWriteCloser = (*Conn)(nil)

func TestLargePacket(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	serverConnCh := make(chan net.Conn, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		serverConnCh <- conn
	}()

	conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i)
	}

	_, err = conn.Write(largeData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	serverConn := <-serverConnCh
	if serverConn == nil {
		t.Fatal("Accept failed")
	}
	defer serverConn.Close()

	buf := make([]byte, 1024)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Server read failed: %v", err)
	}

	_, err = serverConn.Write(buf[:n])
	if err != nil {
		t.Fatalf("Server write failed: %v", err)
	}

	readBuf := make([]byte, 1024)
	n, err = conn.Read(readBuf)
	if err != nil {
		t.Fatalf("Client read failed: %v", err)
	}

	if n != 1024 {
		t.Errorf("expected 1024 bytes, got %d", n)
	}

	for i := 0; i < 1024; i++ {
		if readBuf[i] != byte(i) {
			t.Errorf("data mismatch at index %d", i)
			break
		}
	}

	lis.Close()
}

func TestSessionRecovery(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer lis.Close()

	var kid uint64
	var serverConn net.Conn

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		serverConn = conn
		kid = conn.(*Conn).kid
	}()

	conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	testData := []byte("hello session")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	wg.Wait()
	defer serverConn.Close()
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Server read failed: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("data mismatch: got %s, want %s", string(buf[:n]), string(testData))
	}

	var wg2 sync.WaitGroup
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		conn2, err := lis.Accept()
		if err != nil {
			return
		}
		n, err := conn2.Read(buf)
		if err != nil {
			t.Logf("Server read after recover failed: %v", err)
			return
		}
		if string(buf[:n]) != "recovered data" {
			t.Logf("recovered data mismatch: got %s, want %s", string(buf[:n]), "recovered data")
		}
	}()

	time.Sleep(time.Millisecond * 100)
	recoverConn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Recover dial failed: %v", err)
	}
	defer recoverConn.Close()

	err = recoverConn.Recover(kid, []byte("recovered data"))
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}

	wg2.Wait()
}

func TestSessionNotFound(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedCert("test-server", time.Now(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	cert, keyBytes, err := parseCertAndKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parseCertAndKey failed: %v", err)
	}

	srv, err := NewServerFromMem(cert, keyBytes)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer lis.Close()

	var serverConn net.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		serverConn = conn
	}()

	conn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	_, err = conn.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	wg.Wait()
	defer serverConn.Close()
	defer conn.Close()

	buf := make([]byte, 1024)
	_, err = serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Server read failed: %v", err)
	}

	var wg2 sync.WaitGroup
	wg2.Add(1)
	var gotErr error
	go func() {
		defer wg2.Done()
		conn2, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn2.Close()
		buf := make([]byte, 1024)
		_, err = conn2.Read(buf)
		if err != nil {
			gotErr = err
		}
	}()

	time.Sleep(time.Millisecond * 100)
	badKid := uint64(999999)
	recoverConn, err := DialWithCert("tcp", lis.Addr().String(), cert)
	if err != nil {
		t.Fatalf("Recover dial failed: %v", err)
	}

	err = recoverConn.Recover(badKid, []byte("test"))
	if err != nil {
		t.Fatalf("Recover send failed: %v", err)
	}

	wg2.Wait()
	if gotErr == nil {
		t.Error("expected server to close connection for invalid kid")
	}
	recoverConn.Close()
}
