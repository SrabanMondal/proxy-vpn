// Demultiplexer reads inbound UDP packets from clients and sets tcp relay for each session
package server

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/SrabanMondal/proxy-vpn/internal/pool"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol/header"
	"github.com/SrabanMondal/proxy-vpn/internal/session"
)

type Demultiplexer struct {
	UDPConn     *net.UDPConn
	Registry    *session.Registry
	Parser      *protocol.Parser
	Builder     *protocol.Builder
	Multiplexer *Multiplexer
	IdleTimeout time.Duration
	earlyData   map[uint32][]earlyDataPacket
	done        chan struct{}
	wg          sync.WaitGroup
}

type earlyDataPacket struct {
	seqID   uint32
	payload []byte
	buffer  []byte
}

func NewDemultiplexer(conn *net.UDPConn, registry *session.Registry, parser *protocol.Parser, multiplexer *Multiplexer, builder *protocol.Builder, idleTimeout time.Duration) *Demultiplexer {
	if idleTimeout <= 0 {
		idleTimeout = 120 * time.Second
	}

	return &Demultiplexer{
		UDPConn:     conn,
		Registry:    registry,
		Parser:      parser,
		Multiplexer: multiplexer,
		Builder:     builder,
		IdleTimeout: idleTimeout,
		earlyData:   make(map[uint32][]earlyDataPacket),
		done:        make(chan struct{}),
	}
}

func (d *Demultiplexer) Start() {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		for {
			buf := pool.Get()
			n, clientAddr, err := d.UDPConn.ReadFromUDP(buf)
			if err != nil {
				pool.Put(buf)
				select {
				case <-d.done:
					return
				default:
					continue
				}
			}

			d.handlePacket(buf, n, clientAddr)
		}
	}()
}

func (d *Demultiplexer) Close() {
	close(d.done)
	d.UDPConn.Close()
	d.wg.Wait()

	for sessionID, queued := range d.earlyData {
		for _, item := range queued {
			pool.Put(item.buffer)
		}
		delete(d.earlyData, sessionID)
	}
}

func (d *Demultiplexer) handlePacket(buf []byte, n int, clientAddr *net.UDPAddr) {
	pkt, err := d.Parser.Parse(buf[:n], buf)
	if err != nil {
		pool.Put(buf)
		return
	}
	log.Printf(
		"[SERVER-DEMUX] Packet Header: session=%d seq=%d type=%d length=%d",
		pkt.Header.SessionID,
		pkt.Header.SeqID,
		pkt.Header.Type,
		pkt.Header.Length,
	)

	sess, ok := d.Registry.Get(pkt.Header.SessionID)

	switch pkt.Header.Type {
	case header.TYPE_CONNECT:
		if !ok {
			// Register pending session before dialing so early DATA is buffered, not dropped.
			sess = session.NewPendingServerSession(clientAddr)
			d.Registry.Add(pkt.Header.SessionID, sess)
			if queued, found := d.earlyData[pkt.Header.SessionID]; found {
				for _, item := range queued {
					sess.InsertPacket(item.seqID, item.payload, item.buffer)
				}
				delete(d.earlyData, pkt.Header.SessionID)
			}
			go d.setupAndRelay(pkt.Header.SessionID, string(pkt.Payload), clientAddr)
		}
		pool.Put(buf)

	case header.TYPE_DATA:
		if !ok {
			log.Printf("[session %d] DATA arrived before CONNECT; buffering until session is registered", pkt.Header.SessionID)
			d.earlyData[pkt.Header.SessionID] = append(d.earlyData[pkt.Header.SessionID], earlyDataPacket{
				seqID:   pkt.Header.SeqID,
				payload: pkt.Payload,
				buffer:  buf,
			})
			return
		}
		sess.InsertPacket(pkt.Header.SeqID, pkt.Payload, buf)

	case header.TYPE_FIN:
		if ok {
			d.Registry.Delete(pkt.Header.SessionID)
			sess.Close()
		}
		if queued, found := d.earlyData[pkt.Header.SessionID]; found {
			for _, item := range queued {
				pool.Put(item.buffer)
			}
			delete(d.earlyData, pkt.Header.SessionID)
		}
		pool.Put(buf)

	default:
		pool.Put(buf)
	}
}

func (d *Demultiplexer) setupAndRelay(sessionID uint32, targetAddr string, clientAddr *net.UDPAddr) {
	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		log.Printf("Failed to dial %s: %v", targetAddr, err)
		d.sendFINWithRetry(sessionID, clientAddr, 0)
		if sess, ok := d.Registry.Get(sessionID); ok {
			d.Registry.Delete(sessionID)
			sess.Close()
		}
		return
	}

	sess, ok := d.Registry.Get(sessionID)
	if !ok {
		conn.Close()
		d.sendFINWithRetry(sessionID, clientAddr, 0)
		return
	}

	sess.SetTargetConn(conn)
	log.Printf("[session %d] connection established: client=%s → target=%s (local=%s)",
		sessionID,
		sess.ClientAddr,
		targetAddr,
		conn.LocalAddr(),
	)

	d.runTCPRelay(sess, sessionID)

	d.Registry.Delete(sessionID)
	sess.Close()
}

func (d *Demultiplexer) runTCPRelay(sess *session.SessionContext, sessionID uint32) {
	var seqID uint32
	defer func() {
		d.sendFINWithRetry(sessionID, sess.ClientAddr, seqID)
	}()

	for {
		buf := pool.Get()
		sess.TargetConn.SetReadDeadline(time.Now().Add(d.IdleTimeout))
		n, err := sess.TargetConn.Read(buf[header.HeaderSize:1460])
		if err != nil {
			pool.Put(buf)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				log.Printf("[session %d] idle timeout, closing", sessionID)
				break
			}

			if errors.Is(err, io.EOF) {
				log.Printf("[session %d] target closed", sessionID)
				break
			}

			log.Printf("[session %d] read error: %v", sessionID, err)
			break
		}

		pkt := protocol.NewPacket(sessionID, header.TYPE_DATA, seqID, buf[header.HeaderSize:header.HeaderSize+n], buf)
		work, err := d.Builder.Build(pkt)
		if err != nil {
			log.Printf("Builder error: %q", err)
			pool.Put(buf)
			continue
		}

		if !d.Multiplexer.Send(OutboundPacket{
			Data:   work.Data,
			Addr:   sess.ClientAddr,
			Buffer: work.OriginalBuffer,
		}, 2*time.Second) {
			log.Printf("[session %d] outbound queue timeout, closing session", sessionID)
			pool.Put(work.OriginalBuffer)
			break
		}

		seqID++
	}
}

func (d *Demultiplexer) sendFINWithRetry(sessionID uint32, addr *net.UDPAddr, seqID uint32) {
	if addr == nil {
		return
	}

	for i := 0; i < 3; i++ {
		buf := pool.Get()
		finPkt := protocol.NewPacket(sessionID, header.TYPE_FIN, seqID, buf[header.HeaderSize:header.HeaderSize], buf)
		work, err := d.Builder.Build(finPkt)
		if err != nil {
			pool.Put(buf)
			continue
		}

		if d.Multiplexer.Send(OutboundPacket{
			Data:   work.Data,
			Addr:   addr,
			Buffer: work.OriginalBuffer,
		}, 500*time.Millisecond) {
			return
		}

		pool.Put(work.OriginalBuffer)
	}

	log.Printf("[session %d] failed to deliver FIN after retries", sessionID)
}
