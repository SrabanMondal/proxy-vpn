package client

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/SrabanMondal/proxy-vpn/internal/pool"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol/header"
	"github.com/SrabanMondal/proxy-vpn/internal/session"
)

// HandleBrowserSession manages a single browser connection
func HandleBrowserSession(
	browserConn net.Conn,
	registry *session.Registry,
	multiplexer *Multiplexer,
	builder *protocol.Builder,
	idleTimeout time.Duration,
) {
	defer browserConn.Close()
	if idleTimeout <= 0 {
		idleTimeout = 120 * time.Second
	}

	// 1. SOCKS5 handshake
	targetAddr, err := PerformSOCKS5Handshake(browserConn)
	if err != nil {
		log.Println("SOCKS5 handshake failed:", err)
		return
	}
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		log.Printf("[SERVER] Invalid target address from CONNECT packet: %q, error: %v", targetAddr, err)
		return
	}
	log.Printf("[SOCKS5] IP address: %s Port: %s", host, port)

	// 2. Generate session ID
	sessID := GenerateSessionID()

	// 3. Create session context
	sess := session.NewSession(browserConn)
	registry.Add(sessID, sess)
	defer func() {
		registry.Delete(sessID)
		sess.Close()
	}()

	// 5. Send CONNECT packet to server
	smolbuf := pool.Get()
	copy(smolbuf[header.HeaderSize:], []byte(targetAddr))
	connectPkt := protocol.NewPacket(sessID, header.TYPE_CONNECT, 0, []byte(targetAddr), smolbuf)
	log.Printf("[CLIENT] Packet sent: session=%d, type=%d, payload_len=%d", connectPkt.Header.SessionID, connectPkt.Header.Type, len(connectPkt.Payload))
	//log.Printf("[CLIENT] Sending CONNECT payload: %q", string(connectPkt.Payload))
	data, err := builder.Build(connectPkt)
	//log.Printf("[CLIENT] Sending Encrypted bytes: %q", string(data.Data))
	if err != nil {
		log.Println("failed to build CONNECT packet:", err)
		return
	}
	if !sendOutboundWithTimeout(multiplexer, data, 2*time.Second) {
		log.Printf("[session %d] failed to enqueue CONNECT packet", sessID)
		return
	}

	// 6. Forward Browser -> UDP (server)
	var localSeqID uint32
	for {
		buf := pool.Get()
		browserConn.SetReadDeadline(time.Now().Add(idleTimeout))
		n, err := browserConn.Read(buf[header.HeaderSize:1460])
		//log.Printf("Received Paylod from browser: %q",buf[11:11+n])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				log.Printf("[session %d] idle timeout, closing", sessID)
			}
			if err != io.EOF {
				log.Println("browser read error:", err)
			}
			pool.Put(buf)
			sendFINWithRetry(sessID, builder, multiplexer)
			return
		}

		// Build DATA packet
		pkt := protocol.NewPacket(sessID, header.TYPE_DATA, localSeqID, buf[header.HeaderSize:header.HeaderSize+n], buf)
		localSeqID++
		data, err := builder.Build(pkt)
		if err != nil {
			log.Println("failed to build DATA packet:", err)
			pool.Put(buf)
			continue
		}
		if !sendOutboundWithTimeout(multiplexer, data, 2*time.Second) {
			log.Printf("[session %d] send queue timeout, closing session", sessID)
			sendFINWithRetry(sessID, builder, multiplexer)
			return
		}

	}
}

func sendOutboundWithTimeout(multiplexer *Multiplexer, data protocol.OutboundWork, timeout time.Duration) bool {
	if multiplexer.Send(data, timeout) {
		return true
	}

	if data.OriginalBuffer != nil {
		pool.Put(data.OriginalBuffer)
	}
	return false
}

func sendFINWithRetry(sessionID uint32, builder *protocol.Builder, multiplexer *Multiplexer) {
	for i := 0; i < 3; i++ {
		buf := pool.Get()
		finPkt := protocol.NewPacket(sessionID, header.TYPE_FIN, 0, buf[header.HeaderSize:header.HeaderSize], buf)
		data, err := builder.Build(finPkt)
		if err != nil {
			pool.Put(buf)
			continue
		}

		if sendOutboundWithTimeout(multiplexer, data, 500*time.Millisecond) {
			return
		}
	}

	log.Printf("[session %d] failed to deliver FIN after retries", sessionID)
}
