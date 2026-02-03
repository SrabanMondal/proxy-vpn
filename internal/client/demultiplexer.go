package client

import (
	"log"
	"net"
	"sync"
	//"time"

	"github.com/SrabanMondal/proxy-vpn/internal/pool"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol"
	"github.com/SrabanMondal/proxy-vpn/internal/session"
)

// Demultiplexer reads inbound UDP packets and dispatches them to sessions
type Demultiplexer struct {
	UDPConn *net.UDPConn
	Registry *session.Registry         
	Parser  *protocol.Parser
    done    chan struct{}
    wg      sync.WaitGroup
}

// NewDemultiplexer creates a new Demultiplexer
func NewDemultiplexer(conn *net.UDPConn, registry *session.Registry, parser *protocol.Parser) *Demultiplexer {
	return &Demultiplexer{
		UDPConn:  conn,
		Registry: registry,
		Parser:   parser,
        done:     make(chan struct{}),
	}
}

// Start begins reading UDP packets in a goroutine
func (d *Demultiplexer) Start() {
    d.wg.Add(1)
    go func() {
        defer d.wg.Done()
        for {
            buf := pool.Get()
            //d.UDPConn.SetReadDeadline(time.Now().Add(30*time.Second))

            n, _, err := d.UDPConn.ReadFromUDP(buf)
            if err != nil {
                select {
                case <-d.done:
                    pool.Put(buf)
					return
				default:
                    pool.Put(buf)
				}
                log.Println("demultiplexer read error:", err)
                continue
            }

            d.handlePacket(buf, n)
        }
    }()
}

func (d *Demultiplexer) Close() error {
	close(d.done)

	err := d.UDPConn.Close()

	d.wg.Wait()

	return err
}

func (d *Demultiplexer) handlePacket(b []byte, n int) {
    pkt, err := d.Parser.Parse(b[:n], b)
    if err != nil {
        log.Println("failed to parse packet:", err)
        pool.Put(b) 
        return
    }

    sess, ok := d.Registry.Get(pkt.Header.SessionID)
    if !ok {
        pool.Put(b)
        return
    }
    log.Printf(
        "[CLIENT] Packet Header: session=%d seq=%d type=%d length=%d",
        pkt.Header.SessionID,
        pkt.Header.SeqID,
        pkt.Header.Type,
        pkt.Header.Length,
    )
    // log.Printf(
    //     "[CLIENT] Received payload after parsing (len=%d): %q",
    //     len(pkt.Payload),
    //     pkt.Payload,
    // )

    sess.InsertPacket(pkt.Header.SeqID, pkt.Payload, pkt.Buffer)
}