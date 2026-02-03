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
) {
	defer browserConn.Close()

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
	log.Printf("[SOCKS5] IP address: %s Port: %s", host,port)
	

	// 2. Generate session ID
	sessID := GenerateSessionID()

	// 3. Create session context
	sess := session.NewSession(browserConn)
	registry.Add(sessID, sess)
	defer func() {
		sess.Close()
		registry.Delete(sessID)
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
	multiplexer.SendChan <- data

	// 6. Forward Browser -> UDP (server)
	var localSeqID uint32
	for {
		buf := pool.Get()
		browserConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := browserConn.Read(buf[11:1460])
		//log.Printf("Received Paylod from browser: %q",buf[11:11+n])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
                log.Printf("[session %d] idle timeout, closing", sessID)
            }
			if err != io.EOF {
				log.Println("browser read error:", err)
			}
			pool.Put(buf)
			empty := pool.Get()
			finPkt := protocol.NewPacket(sessID, header.TYPE_FIN, 0, empty[11:1460], empty)
			data, _ := builder.Build(finPkt)
			multiplexer.SendChan <- data
			return
		}

		// Build DATA packet
		pkt := protocol.NewPacket(sessID, header.TYPE_DATA, localSeqID, buf[11:11+n], buf)
		localSeqID++
		data, err := builder.Build(pkt)
		if err != nil {
			log.Println("failed to build DATA packet:", err)
			pool.Put(buf)
			continue
		}
		multiplexer.SendChan <- data;

	}
}
