package stcp

import (
	"net"
)

type Listener struct {
	net.Listener
	server *Server
}

func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	stcpConn := &Conn{Conn: conn}
	if err := stcpConn.serverHandshake(conn, l.server.cert, l.server.privateKey); err != nil {
		conn.Close()
		return nil, err
	}

	return stcpConn, nil
}
