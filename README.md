# STCP 🔐

> A lightweight encrypted TCP connection library for Go, providing end-to-end encryption with ECDH key exchange and AES-256-GCM.

[English](#english) | [中文](#中文)

---

## English

### Features

- 🔒 **End-to-End Encryption** - X25519 ECDH key exchange + AES-256-GCM
- 📜 **Certificate-based Authentication** - Mutual TLS authentication with self-signed certificates
- ⚡ **Nonce-enhanced Key Derivation** - SHA256(ECDH key || clientNonce || serverNonce)
- 🌐 **Standard net.Conn Interface** - Drop-in replacement for standard net.Conn
- 🚀 **High Performance** - Minimal overhead, optimized for low latency
- 🔄 **Session Key Caching** - LRU cache to reduce handshake overhead
- 📦 **Minimal Dependencies** - Zero external dependencies (pure Go)
- ⏱️ **Deadline Support** - Full support for read/write deadlines

### Installation

```bash
go get github.com/wsyqn6/stcp
```

Requires Go 1.26.1 or later.

### Quick Start

#### Server

```go
package main

import (
	"log"
	"io"
	"github.com/wsyqn6/stcp"
)

func main() {
	srv, err := stcp.NewServer("server.crt", "server.key")
	if err != nil {
		log.Fatalf("NewServer failed: %v", err)
	}

	lis, err := srv.Listen("tcp", ":13579")
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}

	log.Printf("server started on %s", lis.Addr())

	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn io.ReadWriteCloser) {
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Read failed: %v", err)
		return
	}

	log.Printf("received: %s", string(buf[:n]))
	conn.Write([]byte("echo: " + string(buf[:n])))
}
```

#### Client

```go
package main

import (
	"log"
	"github.com/wsyqn6/stcp"
)

func main() {
	conn, err := stcp.Dial("tcp", "localhost:13579", "root.crt")
	if err != nil {
		log.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Send message
	_, err = conn.Write([]byte("hello"))
	if err != nil {
		log.Fatalf("Write failed: %v", err)
	}

	// Receive response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}

	log.Printf("received: %s", string(buf[:n]))
}
```

### Generate Certificates

```go
package main

import (
	"time"
	"github.com/wsyqn6/stcp"
)

func main() {
	// Generate self-signed certificate (valid for 1 year)
	certPEM, keyPEM, err := stcp.GenerateSelfSignedCert(
		"server",
		time.Now(),
		time.Now().Add(365*24*time.Hour),
	)
	if err != nil {
		panic(err)
	}

	// Save to files
	// Use certPEM and keyPEM for server
}
```

### API Reference

| Function | Description |
|----------|-------------|
| `NewServer(certFile, keyFile string) (*Server, error)` | Create server with certificate and key files |
| `NewServerFromMem(cert *x509.Certificate, key []byte) (*Server, error)` | Create server from memory |
| `(s *Server) Listen(network, addr string) (net.Listener, error)` | Start listening on given network and address |
| `Dial(network, addr string, rootCertFile string) (*Conn, error)` | Dial with root CA certificate file |
| `DialWithCert(network, addr string, cert *x509.Certificate) (*Conn, error)` | Dial with server certificate |
| `(c *Conn) Read(b []byte) (int, error)` | Read decrypted data |
| `(c *Conn) Write(b []byte) (int, error)` | Write encrypted data |
| `(c *Conn) Close() error` | Close connection |
| `(c *Conn) LocalAddr() net.Addr` | Local address |
| `(c *Conn) RemoteAddr() net.Addr` | Remote address |
| `(c *Conn) SetDeadline(t time.Time) error` | Set read/write deadline |
| `(c *Conn) SetReadDeadline(t time.Time) error` | Set read deadline |
| `(c *Conn) SetWriteDeadline(t time.Time) error` | Set write deadline |

### Certificate Functions

| Function | Description |
|----------|-------------|
| `LoadPemCertficate(file string) (*x509.Certificate, error)` | Load certificate from PEM file |
| `LoadPemCertKey(file string) (crypto.PrivateKey, error)` | Load private key from PEM file |
| `GenerateSelfSignedCert(commonName string, notBefore, notAfter time.Time) ([]byte, []byte, error)` | Generate self-signed certificate |

### Protocol

#### Handshake Flow

1. Client sends: `[6B "STCP"] [32B clientPubKey] [32B clientNonce]`
2. Server validates, generates ECDH shared key
3. Server responds: `[2B certLen] [cert] [32B serverPubKey] [512B sign] [32B serverNonce] [8B kid]`
4. Both derive encryption key: `SHA256(ECDH key || clientNonce || serverNonce)`

#### Packet Format

```
[1B Ver] [1B Type] [1B Status] [1B Flags] [4B Length] [Body]
```

- **Ver**: Protocol version (1)
- **Type**: Packet type (handshake/recover/data)
- **Status**: Success/fail status
- **Flags**: Compression and encryption flags
- **Length**: Body length (4 bytes)
- **Body**: Encrypted payload

### Security Design

#### Key Exchange

- Uses X25519 ECDH for key exchange
- Each session generates ephemeral key pairs
- No long-term key material stored

#### Key Derivation

The final encryption key is derived using:

```
key = SHA256(ECDH_shared_key || clientNonce || serverNonce)
```

This ensures:
- Forward secrecy (session keys not derived from long-term keys)
- Unique key per session (nonces add randomness)
- Resistance against replay attacks

#### Encryption

- AES-256-GCM authenticated encryption
- Random nonce per message (unique per write)
- 16-byte authentication tag

### Benchmark

```bash
go test -bench=. -benchtime=1s ./...
```

Typical results (local loopback):

```
BenchmarkConnWriteRead-8          100000   15000 ns/op
BenchmarkConnParallel-8           500000    3200 ns/op
```

### Why STCP?

| Feature | STCP | TLS | secureio |
|---------|------|-----|----------|
| Protocol | Custom TCP | Standard TLS | Custom |
| Key Exchange | ECDH X25519 | RSA/ECDHE | ECDH |
| Encryption | AES-256-GCM | AES-GCM | XChaCha20 |
| Dependencies | None | None | None |
| net.Conn | ✓ | ✓ | ✗ |

### License

MIT License - see [LICENSE](LICENSE) for details.

---

## 中文

### 功能特性

- 🔒 **端到端加密** - X25519 ECDH 密钥交换 + AES-256-GCM
- 📜 **证书认证** - 自签名证书双向 TLS 认证
- ⚡ **Nonce 增强密钥派生** - SHA256(ECDH密钥 || 客户端Nonce || 服务端Nonce)
- 🌐 **标准 net.Conn 接口** - 可直接替代标准 net.Conn
- 🚀 **高性能** - 极低开销，优化低延迟场景
- 🔄 **会话密钥缓存** - LRU 缓存减少握手开销
- 📦 **最小依赖** - 零外部依赖（纯 Go 实现）
- ⏱️ **超时支持** - 完整支持读写超时

### 安装

```bash
go get github.com/wsyqn6/stcp
```

需要 Go 1.26.1 或更高版本。

### 快速开始

#### 服务端

```go
package main

import (
	"log"
	"io"
	"github.com/wsyqn6/stcp"
)

func main() {
	srv, err := stcp.NewServer("server.crt", "server.key")
	if err != nil {
		log.Fatalf("创建服务器失败: %v", err)
	}

	lis, err := srv.Listen("tcp", ":13579")
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}

	log.Printf("服务器启动于 %s", lis.Addr())

	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn io.ReadWriteCloser) {
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("读取失败: %v", err)
		return
	}

	log.Printf("收到: %s", string(buf[:n]))
	conn.Write([]byte("回显: " + string(buf[:n])))
}
```

#### 客户端

```go
package main

import (
	"log"
	"github.com/wsyqn6/stcp"
)

func main() {
	conn, err := stcp.Dial("tcp", "localhost:13579", "root.crt")
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	// 发送消息
	_, err = conn.Write([]byte("你好"))
	if err != nil {
		log.Fatalf("发送失败: %v", err)
	}

	// 接收响应
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("接收失败: %v", err)
	}

	log.Printf("收到: %s", string(buf[:n]))
}
```

### 生成证书

```go
package main

import (
	"time"
	"github.com/wsyqn6/stcp"
)

func main() {
	// 生成自签名证书（有效期1年）
	certPEM, keyPEM, err := stcp.GenerateSelfSignedCert(
		"server",
		time.Now(),
		time.Now().Add(365*24*time.Hour),
	)
	if err != nil {
		panic(err)
	}

	// 保存到文件
	// 使用 certPEM 和 keyPEM 启动服务器
}
```

### API 参考

| 函数 | 描述 |
|------|------|
| `NewServer(certFile, keyFile string) (*Server, error)` | 使用证书和密钥文件创建服务器 |
| `NewServerFromMem(cert *x509.Certificate, key []byte) (*Server, error)` | 从内存创建服务器 |
| `(s *Server) Listen(network, addr string) (net.Listener, error)` | 在指定网络和地址上开始监听 |
| `Dial(network, addr string, rootCertFile string) (*Conn, error)` | 使用根CA证书文件连接 |
| `DialWithCert(network, addr string, cert *x509.Certificate) (*Conn, error)` | 使用服务器证书连接 |
| `(c *Conn) Read(b []byte) (int, error)` | 读取解密后的数据 |
| `(c *Conn) Write(b []byte) (int, error)` | 写入加密数据 |
| `(c *Conn) Close() error` | 关闭连接 |
| `(c *Conn) LocalAddr() net.Addr` | 本地地址 |
| `(c *Conn) RemoteAddr() net.Addr` | 远程地址 |
| `(c *Conn) SetDeadline(t time.Time) error` | 设置读写超时 |
| `(c *Conn) SetReadDeadline(t time.Time) error` | 设置读取超时 |
| `(c *Conn) SetWriteDeadline(t time.Time) error` | 设置写入超时 |

### 证书相关函数

| 函数 | 描述 |
|------|------|
| `LoadPemCertficate(file string) (*x509.Certificate, error)` | 从PEM文件加载证书 |
| `LoadPemCertKey(file string) (crypto.PrivateKey, error)` | 从PEM文件加载私钥 |
| `GenerateSelfSignedCert(commonName string, notBefore, notAfter time.Time) ([]byte, []byte, error)` | 生成自签名证书 |

### 协议设计

#### 握手流程

1. 客户端发送: `[6B "STCP"] [32B 客户端公钥] [32B 客户端Nonce]`
2. 服务端验证，生成 ECDH 共享密钥
3. 服务端响应: `[2B 证书长度] [证书] [32B 服务端公钥] [512B 签名] [32B 服务端Nonce] [8B 密钥ID]`
4. 双方派生加密密钥: `SHA256(ECDH密钥 || 客户端Nonce || 服务端Nonce)`

#### 数据包格式

```
[1B 版本] [1B 类型] [1B 状态] [1B 标志] [4B 长度] [数据体]
```

- **版本**: 协议版本 (1)
- **类型**: 数据包类型（握手/恢复/数据）
- **状态**: 成功/失败状态
- **标志**: 压缩和加密标志
- **长度**: 数据体长度 (4字节)
- **数据体**: 加密载荷

### 安全设计

#### 密钥交换

- 使用 X25519 ECDH 进行密钥交换
- 每个会话生成临时密钥对
- 不存储长期密钥材料

#### 密钥派生

最终加密密钥通过以下方式派生：

```
密钥 = SHA256(ECDH共享密钥 || 客户端Nonce || 服务端Nonce)
```

确保：
- 前向保密（会话密钥不来自长期密钥）
- 每会话唯一（Nonce增加随机性）
- 抗重放攻击

#### 加密

- AES-256-GCM 认证加密
- 每个消息使用随机Nonce
- 16字节认证标签

### 性能测试

```bash
go test -bench=. -benchtime=1s ./...
```

典型结果（本地回环）:

```
BenchmarkConnWriteRead-8          100000   15000 ns/op
BenchmarkConnParallel-8           500000    3200 ns/op
```

### 为什么选择 STCP？

| 特性 | STCP | TLS | secureio |
|------|------|-----|----------|
| 协议 | 自定义TCP | 标准TLS | 自定义 |
| 密钥交换 | ECDH X25519 | RSA/ECDHE | ECDH |
| 加密 | AES-256-GCM | AES-GCM | XChaCha20 |
| 依赖 | 无 | 无 | 无 |
| net.Conn | ✓ | ✓ | ✗ |

### 许可证

MIT 许可证 - 详见 [LICENSE](LICENSE)。

---

<p align="center">
  <a href="https://pkg.go.dev/github.com/wsyqn6/stcp">📚 GoDoc</a> •
  <a href="https://github.com/wsyqn6/stcp/issues">🐛 Issues</a>
</p>
