package client

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
)

// PerformSOCKS5Handshake performs SOCKS5 handshake and returns the target address in "host:port" format
func PerformSOCKS5Handshake(conn net.Conn) (string, error) {
	buf := make([]byte, 260)

	// --- Step 1: Greeting ---
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil {
		log.Printf("[SOCKS5] Error reading greeting: %v", err)
		return "", err
	}

	if buf[0] != 0x05 {
		log.Printf("[SOCKS5] Invalid version: 0x%02x", buf[0])
		return "", errors.New("invalid SOCKS version")
	}

	numMethods := int(buf[1])
	log.Printf("[SOCKS5] Greeting raw (%d bytes): % x", n, buf[:n])
	log.Printf("[SOCKS5] Number of methods: %d", numMethods)

	if n < 2+numMethods {
		log.Printf("[SOCKS5] Reading %d more method bytes", (2+numMethods)-n)
		_, err = io.ReadFull(conn, buf[n:2+numMethods])
		if err != nil {
			log.Printf("[SOCKS5] Error reading methods: %v", err)
			return "", err
		}
	}

	log.Printf("[SOCKS5] Methods: % x", buf[2:2+numMethods])

	// --- Step 2: Select method ---
	log.Printf("[SOCKS5] Sending method selection: 05 00 (no auth)")
	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		log.Printf("[SOCKS5] Error sending method selection: %v", err)
		return "", err
	}

	// --- Step 3: Read request header (4 bytes) ---
	_, err = io.ReadFull(conn, buf[:4])
	if err != nil {
		log.Printf("[SOCKS5] Error reading request header: %v", err)
		return "", err
	}

	if buf[0] != 0x05 || buf[1] != 0x01 {
		log.Printf("[SOCKS5] Unsupported command: VER=0x%02x CMD=0x%02x", buf[0], buf[1])
		return "", errors.New("unsupported SOCKS command")
	}

	addrType := buf[3]
	var host string
	log.Printf("[SOCKS5] Address type: 0x%02x", addrType)

	// --- Step 3a: Read address based on type ---
	switch addrType {
	case 0x01: // IPv4
		_, err = io.ReadFull(conn, buf[:4])
		if err != nil {
			log.Printf("[SOCKS5] Error reading IPv4: %v", err)
			return "", err
		}
		host = net.IP(buf[:4]).String()
		log.Printf("[SOCKS5] IPv4 address: %s", host)

	case 0x03: // Domain
		_, err = io.ReadFull(conn, buf[:1])
		if err != nil {
			log.Printf("[SOCKS5] Error reading domain length: %v", err)
			return "", err
		}
		l := int(buf[0])
		log.Printf("[SOCKS5] Domain length: %d", l)

		_, err = io.ReadFull(conn, buf[:l])
		if err != nil {
			log.Printf("[SOCKS5] Error reading domain: %v", err)
			return "", err
		}
		host = string(buf[:l])
		log.Printf("[SOCKS5] Domain: %s", host)

	case 0x04: // IPv6
		_, err = io.ReadFull(conn, buf[:16])
		if err != nil {
			log.Printf("[SOCKS5] Error reading IPv6: %v", err)
			return "", err
		}
		host = net.IP(buf[:16]).String()
		log.Printf("[SOCKS5] IPv6 address: %s", host)

	default:
		log.Printf("[SOCKS5] Unsupported address type: 0x%02x", addrType)
		return "", errors.New("unsupported address type")
	}

	// --- Step 3b: Read port ---
	_, err = io.ReadFull(conn, buf[:2])
	if err != nil {
		log.Printf("[SOCKS5] Error reading port: %v", err)
		return "", err
	}
	port := binary.BigEndian.Uint16(buf[:2])
	log.Printf("[SOCKS5] Port: %d", port)

	// --- Step 4: Send success reply ---
	reply := []byte{0x05, 0x00, 0x00, 0x01} // IPv4 0.0.0.0
	reply = append(reply, 0, 0, 0, 0)       // BND.ADDR
	reply = append(reply, 0, 0)             // BND.PORT

	log.Printf("[SOCKS5] Sending success reply")
	_, _ = conn.Write(reply)
	log.Printf("[SOCKS5] Handshake complete → %s:%d", host, port)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

