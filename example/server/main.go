package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wsyqn6/stcp"
)

func main() {
	certFile := "example/intermediate.crt"
	keyFile := "example/intermediate.key"

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Fatalf("Certificate file not found: %s", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatalf("Key file not found: %s", keyFile)
	}

	srv, err := stcp.NewServer(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	lis, err := srv.Listen("tcp", ":13579")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Server started on %s", lis.Addr())
	log.Printf("Press Ctrl+C to stop")

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down server...")
		lis.Close()
	}()

	for {
		conn, err := lis.Accept()
		if err != nil {
			if lis.Close() != nil {
				break
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	stcpConn, ok := conn.(*stcp.Conn)
	if !ok {
		log.Printf("Invalid connection type")
		return
	}
	defer stcpConn.Close()

	remoteAddr := stcpConn.RemoteAddr().String()
	log.Printf("New connection from %s", remoteAddr)

	buf := make([]byte, 4096)

	for {
		stcpConn.SetReadDeadline(time.Now().Add(60 * time.Second))

		n, err := stcpConn.Read(buf)
		if err != nil {
			log.Printf("Connection from %s closed: %v", remoteAddr, err)
			return
		}

		data := string(buf[:n])
		log.Printf("Received from %s: %s", remoteAddr, data)

		response := "echo: " + data
		_, err = stcpConn.Write([]byte(response))
		if err != nil {
			log.Printf("Write error to %s: %v", remoteAddr, err)
			return
		}
	}
}
