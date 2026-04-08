package stcp

import (
	"crypto/x509"
	"net"
)

type Server struct {
	cert       *x509.Certificate
	privateKey any
}

func NewServer(certFile, keyFile string) (*Server, error) {
	cert, err := LoadPemCertficate(certFile)
	if err != nil {
		return nil, err
	}

	key, err := LoadPemCertKey(keyFile)
	if err != nil {
		return nil, err
	}

	return &Server{cert: cert, privateKey: key}, nil
}

func NewServerFromMem(cert *x509.Certificate, key []byte) (*Server, error) {
	privateKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Server{cert: cert, privateKey: privateKey}, nil
}

func (s *Server) Listen(network, addr string) (net.Listener, error) {
	lis, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &Listener{Listener: lis, server: s}, nil
}
