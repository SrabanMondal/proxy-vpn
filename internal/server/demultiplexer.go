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
	done        chan struct{}
	wg          sync.WaitGroup
}

func NewDemultiplexer(conn *net.UDPConn, registry *session.Registry, parser *protocol.Parser, multiplexer *Multiplexer, builder *protocol.Builder) *Demultiplexer {
	return &Demultiplexer{
		UDPConn:     conn,
		Registry:    registry,
		Parser:      parser,
		Multiplexer: multiplexer,
		Builder:     builder,
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
}

func (d *Demultiplexer) handlePacket(buf []byte, n int, clientAddr *net.UDPAddr) {
   // log.Printf("[SERVER] Received Encrypted bytes: %q", string(buf[:n]))
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

    // log.Printf(
    //     "[SERVER-DEMUX] Received payload after parsing (len=%d): %q",
    //     len(pkt.Payload),
    //     pkt.Payload,
    // )



    sess, ok := d.Registry.Get(pkt.Header.SessionID)

    switch pkt.Header.Type {
    case header.TYPE_CONNECT:
        if !ok {
            go d.setupAndRelay(pkt.Header.SessionID, string(pkt.Payload), clientAddr)
        }
        pool.Put(buf)

    case header.TYPE_DATA:
        if ok {
            sess.InsertPacket(pkt.Header.SeqID, pkt.Payload, buf)
        } else {
            pool.Put(buf)
        }

    case header.TYPE_FIN:
        if ok {
            sess.Close()
            d.Registry.Delete(pkt.Header.SessionID)
        }
        pool.Put(buf)

    default:
        pool.Put(buf)
    }
}

func (d *Demultiplexer) setupAndRelay(sessionID uint32, targetAddr string, clientAddr *net.UDPAddr) {
    // 1. Dial the website (Blocking)
    
    conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
    if err != nil {
        log.Printf("Failed to dial %s: %v", targetAddr, err)
        return
    }
     log.Printf("[session %d] connection established: client=%s → target=%s (local=%s)",
        sessionID,
        clientAddr,           // incoming UDP client
        targetAddr,           // website dialed
        conn.LocalAddr(),     // local outbound IP:port
    )
    // 2. Setup Session
    sess := session.NewSession(conn)
    sess.ClientAddr = clientAddr
    d.Registry.Add(sessionID, sess)

    // 3. Enter the Relay Loop (Synchronous in this goroutine)
    d.runTCPRelay(sess, sessionID)

    // 4. Cleanup when the loop breaks
    d.Registry.Delete(sessionID)
    sess.Close()
}


func (d *Demultiplexer) runTCPRelay(sess *session.SessionContext, sessionID uint32) {
    var seqID uint32
    defer func() {
        buf := pool.Get()
        finPkt := protocol.NewPacket(sessionID, header.TYPE_FIN, seqID, buf[11:1460], buf)
        work, err := d.Builder.Build(finPkt)
        if err == nil {
            select{
                case d.Multiplexer.SendChan <- OutboundPacket{
                    Data:   work.Data,
                    Addr:   sess.ClientAddr,
                    Buffer: buf,
                }:
                default:
                    log.Printf("[session %d] FIN send dropped (channel full/closed)", sessionID)
            }
        }
        sess.Close()
    }()

    for {
        buf := pool.Get()
        sess.TargetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
        n, err := sess.TargetConn.Read(buf[11:1460])
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

            // other error
            log.Printf("[session %d] read error: %v", sessionID, err)
            break
        }
        // log.Printf("Received Paylod with (len=%d) from target connection: %q",n,buf[11:11+n])
       
		pkt := protocol.NewPacket(sessionID, header.TYPE_DATA, seqID, buf[11:11+n], buf)
        work, err := d.Builder.Build(pkt) 
        if err != nil {
            log.Printf("Builder error: %q",err)
            pool.Put(buf)
            continue
        }

        select {
            case d.Multiplexer.SendChan <- OutboundPacket{
                Data:           work.Data,
                Addr:           sess.ClientAddr,
                Buffer:         work.OriginalBuffer,
            }:
            case <-sess.Quit:
                pool.Put(work.OriginalBuffer)
                return
        }
        
        seqID++
    }
}
