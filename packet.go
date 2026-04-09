package stcp

import (
	"encoding/binary"
	"io"
	"math"
)

const (
	Version       = 1
	HeaderLength  = 10
	ECDHKeyLength = 32
	NonceLength   = 32
	Stcp          = "STCP"
	MaxPacketSize = 64 * 1024
	MaxBodySize   = MaxPacketSize - HeaderLength
)

type HeaderType = byte

const (
	HeaderTypeCryptoHandshake HeaderType = iota + 1
	HeaderTypeCryptoRecover
	HeaderTypeCryptoData
)

type HeaderStatus = byte

const (
	HeaderStatusSuccess       HeaderStatus = 0
	HeaderStatusFail          HeaderStatus = 1
	HeaderStatusTimeout       HeaderStatus = 2
	HeaderStatusInvalidHeader HeaderStatus = 3
	HeaderStatusInvalidBody   HeaderStatus = 4
)

type HeaderFlags = byte

const (
	HeaderFlagCompressed HeaderFlags = 1 << iota
	HeaderFlagEncrypted
)

type Header [HeaderLength]byte

func (h Header) Version() byte {
	return h[0]
}

func (h *Header) setVersion(v byte) {
	h[0] = v
}

func (h Header) Type() byte {
	return h[1]
}

func (h *Header) setType(v byte) {
	h[1] = v
}

func (h Header) Status() byte {
	return h[2]
}

func (h *Header) setStatus(v byte) {
	h[2] = v
}

func (h Header) Flags() byte {
	return h[3]
}

func (h *Header) setFlags(v byte) {
	h[3] = v
}

func (h Header) ContentLength() uint32 {
	return binary.BigEndian.Uint32(h[4:])
}

func (h *Header) setContentLength(v uint32) {
	binary.BigEndian.PutUint32(h[4:], v)
}

func ReadHeader(r io.Reader) (*Header, error) {
	var h Header
	_, err := io.ReadFull(r, h[:])
	if err != nil {
		return nil, err
	}
	if h.Version() != Version {
		return nil, ErrInvalidVersion
	}
	return &h, nil
}

func (h Header) ReadBody(r io.Reader) ([]byte, error) {
	cl := h.ContentLength()
	if cl == 0 {
		return nil, ErrEmptyBody
	}
	if cl > MaxBodySize {
		return nil, ErrPacketTooLarge
	}
	body := make([]byte, cl)
	_, err := io.ReadFull(r, body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

type Packet struct {
	Header
	Body []byte
}

func newHeader(ht, status byte, bodyLen uint32) Header {
	var h Header
	h.setVersion(Version)
	h.setType(ht)
	h.setStatus(status)
	h.setContentLength(bodyLen)
	return h
}

func NewPacket(ht, status byte, body ...[]byte) (*Packet, error) {
	var h Header
	h.setVersion(Version)
	h.setType(ht)
	h.setStatus(status)

	var p = Packet{Header: h}

	if len(body) > 0 {
		if len(body[0]) > math.MaxUint32 {
			return nil, ErrBodyToolong
		}
		p.setContentLength(uint32(len(body[0])))
		p.Body = body[0]
	}
	return &p, nil
}

func (p Packet) Data() []byte {
	buf := make([]byte, HeaderLength+len(p.Body))
	copy(buf, p.Header[:])
	copy(buf[HeaderLength:], p.Body)
	return buf
}

func (p Packet) Send(w io.Writer) error {
	_, err := w.Write(p.Data())
	return err
}

func Send(w io.Writer, ht, status byte, body ...[]byte) error {
	p, err := NewPacket(ht, status, body...)
	if err != nil {
		return err
	}
	return p.Send(w)
}

func SendFail(w io.Writer, ht byte, body ...[]byte) error {
	p, err := NewPacket(ht, HeaderStatusFail, body...)
	if err != nil {
		return err
	}
	return p.Send(w)
}

func SendOk(w io.Writer, ht byte, body ...[]byte) error {
	p, err := NewPacket(ht, HeaderStatusSuccess, body...)
	if err != nil {
		return err
	}
	return p.Send(w)
}
