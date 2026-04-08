package main

import (
	"log"
	"time"

	"github.com/wsyqn6/stcp"
)

func main() {
	rootCertFile := "example/root.crt"

	serverAddr := "localhost:13579"

	log.Printf("Connecting to %s", serverAddr)

	conn, err := stcp.Dial("tcp", serverAddr, rootCertFile)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	log.Printf("Connected to %s", conn.RemoteAddr())

	// Send messages
	messages := []string{
		"Hello, Server!",
		"How are you?",
		"Goodbye!",
	}

	for i, msg := range messages {
		log.Printf("Sending message %d: %s", i+1, msg)

		_, err := conn.Write([]byte(msg))
		if err != nil {
			log.Fatalf("Failed to write: %v", err)
		}

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("Failed to read: %v", err)
		}

		log.Printf("Received response: %s", string(buf[:n]))

		// Wait a bit between messages
		if i < len(messages)-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	log.Println("Client finished successfully")
}
