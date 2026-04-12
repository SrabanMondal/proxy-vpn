package client

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/SrabanMondal/proxy-vpn/internal/pool"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol"
)

// Multiplexer manages the global outbound UDP queue.
type Multiplexer struct {
	SendChan chan protocol.OutboundWork // channel for all outbound packets from client
	UDPConn  *net.UDPConn               // vps server connection
	wg       sync.WaitGroup
	quit     chan bool
}

// NewMultiplexer creates a Multiplexer with the given UDP connection and buffer size
func NewMultiplexer(conn *net.UDPConn, queueSize int) *Multiplexer {
	return &Multiplexer{
		SendChan: make(chan protocol.OutboundWork, queueSize),
		UDPConn:  conn,
		quit:     make(chan bool, 1),
	}
}

// Start launches the multiplexer loop in a goroutine
func (m *Multiplexer) Start() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			select {
			case work := <-m.SendChan:
				if m.UDPConn != nil {
					_, err := m.UDPConn.Write(work.Data)
					if err != nil {
						log.Println("client multiplexer write error:", err)
					}
				}
				pool.Put(work.OriginalBuffer)
			case <-m.quit:
				return
			}
		}
	}()
}

// Stop signals the multiplexer to stop and waits for it
func (m *Multiplexer) Stop() {
	select {
	case m.quit <- true:
	default:
	}
	m.wg.Wait()
}

// Send enqueues an outbound packet with timeout to prevent indefinite blocking.
func (m *Multiplexer) Send(work protocol.OutboundWork, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case m.SendChan <- work:
		return true
	case <-timer.C:
		return false
	}
}
