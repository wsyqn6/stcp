package stcp

import (
	"crypto/x509"
	"net"
)

func Dial(network, addr string, rootCertFile string) (*Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	rootCert, err := LoadPemCertficate(rootCertFile)
	if err != nil {
		conn.Close()
		return nil, err
	}

	stcpConn := &Conn{Conn: conn}
	if err := stcpConn.clientHandshake(conn, nil, rootCert); err != nil {
		conn.Close()
		return nil, err
	}

	return stcpConn, nil
}

func DialWithCert(network, addr string, cert *x509.Certificate) (*Conn, error) {
	return DialWithCertAndKey(network, addr, cert, nil)
}

func DialWithCertAndKey(network, addr string, cert *x509.Certificate, clientKey any) (*Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	stcpConn := &Conn{Conn: conn}
	if err := stcpConn.clientHandshake(conn, cert, nil); err != nil {
		conn.Close()
		return nil, err
	}

	return stcpConn, nil
}
