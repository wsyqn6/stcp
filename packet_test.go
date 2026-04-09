package stcp

import (
	"bytes"
	"io"
	"testing"
)

func TestHeaderReadWrite(t *testing.T) {
	original := newHeader(HeaderTypeCryptoData, HeaderStatusSuccess, 1234)

	var buf bytes.Buffer
	_, err := buf.Write(original[:])
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	loaded, err := ReadHeader(&buf)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	if loaded.Version() != original.Version() {
		t.Errorf("version mismatch: got %d, want %d", loaded.Version(), original.Version())
	}

	if loaded.Type() != original.Type() {
		t.Errorf("type mismatch: got %d, want %d", loaded.Type(), original.Type())
	}

	if loaded.Status() != original.Status() {
		t.Errorf("status mismatch: got %d, want %d", loaded.Status(), original.Status())
	}

	if loaded.ContentLength() != original.ContentLength() {
		t.Errorf("content length mismatch: got %d, want %d", loaded.ContentLength(), original.ContentLength())
	}
}

func TestHeaderVersion(t *testing.T) {
	h := newHeader(HeaderTypeCryptoHandshake, HeaderStatusSuccess, 100)
	if h.Version() != Version {
		t.Errorf("expected version %d, got %d", Version, h.Version())
	}
}

func TestHeaderType(t *testing.T) {
	tests := []struct {
		ht       byte
		expected byte
	}{
		{HeaderTypeCryptoHandshake, 1},
		{HeaderTypeCryptoRecover, 2},
		{HeaderTypeCryptoData, 3},
	}

	for _, tt := range tests {
		h := newHeader(tt.ht, HeaderStatusSuccess, 0)
		if h.Type() != tt.expected {
			t.Errorf("type mismatch: got %d, want %d", h.Type(), tt.expected)
		}
	}
}

func TestHeaderStatus(t *testing.T) {
	tests := []struct {
		status   byte
		expected byte
	}{
		{HeaderStatusSuccess, 0},
		{HeaderStatusFail, 1},
		{HeaderStatusTimeout, 2},
		{HeaderStatusInvalidHeader, 3},
		{HeaderStatusInvalidBody, 4},
	}

	for _, tt := range tests {
		h := newHeader(HeaderTypeCryptoData, tt.status, 0)
		if h.Status() != tt.expected {
			t.Errorf("status mismatch: got %d, want %d", h.Status(), tt.expected)
		}
	}
}

func TestNewPacket(t *testing.T) {
	body := []byte("test body")
	pkt, err := NewPacket(HeaderTypeCryptoData, HeaderStatusSuccess, body)
	if err != nil {
		t.Fatalf("NewPacket failed: %v", err)
	}

	if pkt.ContentLength() != uint32(len(body)) {
		t.Errorf("content length mismatch: got %d, want %d", pkt.ContentLength(), len(body))
	}

	if !bytes.Equal(pkt.Body, body) {
		t.Error("body mismatch")
	}
}

func TestNewPacketEmptyBody(t *testing.T) {
	pkt, err := NewPacket(HeaderTypeCryptoData, HeaderStatusSuccess)
	if err != nil {
		t.Fatalf("NewPacket failed: %v", err)
	}

	if pkt.ContentLength() != 0 {
		t.Errorf("expected empty body, got %d", pkt.ContentLength())
	}
}

func TestPacketData(t *testing.T) {
	body := []byte("test data")
	pkt, err := NewPacket(HeaderTypeCryptoData, HeaderStatusSuccess, body)
	if err != nil {
		t.Fatalf("NewPacket failed: %v", err)
	}

	data := pkt.Data()
	if len(data) != HeaderLength+len(body) {
		t.Errorf("data length mismatch: got %d, want %d", len(data), HeaderLength+len(body))
	}
}

func TestSendOk(t *testing.T) {
	var buf bytes.Buffer
	body := []byte("response")

	err := SendOk(&buf, HeaderTypeCryptoHandshake, body)
	if err != nil {
		t.Fatalf("SendOk failed: %v", err)
	}

	var h Header
	_, err = io.ReadFull(&buf, h[:])
	if err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	if h.Type() != HeaderTypeCryptoHandshake {
		t.Errorf("type mismatch: got %d, want %d", h.Type(), HeaderTypeCryptoHandshake)
	}

	if h.Status() != HeaderStatusSuccess {
		t.Errorf("status mismatch: got %d, want %d", h.Status(), HeaderStatusSuccess)
	}
}

func TestSendFail(t *testing.T) {
	var buf bytes.Buffer

	err := SendFail(&buf, HeaderTypeCryptoHandshake)
	if err != nil {
		t.Fatalf("SendFail failed: %v", err)
	}

	var h Header
	_, err = io.ReadFull(&buf, h[:])
	if err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	if h.Status() != HeaderStatusFail {
		t.Errorf("status mismatch: got %d, want %d", h.Status(), HeaderStatusFail)
	}
}

func TestConstants(t *testing.T) {
	if Version != 1 {
		t.Errorf("expected Version 1, got %d", Version)
	}

	if HeaderLength != 10 {
		t.Errorf("expected HeaderLength 10, got %d", HeaderLength)
	}

	if ECDHKeyLength != 32 {
		t.Errorf("expected ECDHKeyLength 32, got %d", ECDHKeyLength)
	}

	if NonceLength != 32 {
		t.Errorf("expected NonceLength 32, got %d", NonceLength)
	}

	if Stcp != "STCP" {
		t.Errorf("expected Spider 'STCP', got '%s'", Stcp)
	}
}

func TestMaxPacketSize(t *testing.T) {
	if MaxPacketSize != 64*1024 {
		t.Errorf("expected MaxPacketSize 65536, got %d", MaxPacketSize)
	}

	if MaxBodySize != MaxPacketSize-HeaderLength {
		t.Errorf("MaxBodySize should be MaxPacketSize - HeaderLength")
	}
}

func TestReadBodyTooLarge(t *testing.T) {
	h := newHeader(HeaderTypeCryptoData, HeaderStatusSuccess, MaxBodySize+1)

	var buf bytes.Buffer
	buf.Write(h[:])

	for i := 0; i < int(MaxBodySize+1); i++ {
		buf.WriteByte(0)
	}

	loaded, err := ReadHeader(&buf)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	_, err = loaded.ReadBody(&buf)
	if err != ErrPacketTooLarge {
		t.Errorf("expected ErrPacketTooLarge, got %v", err)
	}
}
