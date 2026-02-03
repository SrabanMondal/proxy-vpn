// Multiplexer takes all incoming udp packets from server and shoves them to client IP in single stream
package server

import (
	"log"
	"net"
	"sync"

	"github.com/SrabanMondal/proxy-vpn/internal/pool"
)

type OutboundPacket struct {
	Data   []byte      
	Buffer []byte       
	Addr   *net.UDPAddr
}

type Multiplexer struct {
	SendChan chan OutboundPacket
	UDPConn  *net.UDPConn
	wg       sync.WaitGroup
	quit     chan struct{}
	stopOnce   sync.Once
    closeChan  sync.Once
}

func NewMultiplexer(conn *net.UDPConn, queueSize int) *Multiplexer {
	return &Multiplexer{
		SendChan: make(chan OutboundPacket, queueSize),
		UDPConn:  conn,
		quit:     make(chan struct{}),
	}
}

func (m *Multiplexer) Start() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for {
			select {
			case pkt, ok := <-m.SendChan:
				if !ok {
					return 
				}

				log.Printf("[SERVER-MUX] Sending encrypted data len=%d", len(pkt.Data))
				if pkt.Addr != nil {
					_, err := m.UDPConn.WriteToUDP(pkt.Data, pkt.Addr)
					if err != nil {
						log.Println("server multiplexer write error:", err)
					}
				}

				if pkt.Buffer != nil {
					pool.Put(pkt.Buffer)
				}

			case <-m.quit:
				return
			}
		}
	}()
}

// func (m *Multiplexer) Stop() {
// 	close(m.quit)
// 	close(m.SendChan)
// 	m.wg.Wait()
// }
func (m *Multiplexer) Stop() {
    m.stopOnce.Do(func() {
        close(m.quit)

        m.closeChan.Do(func() {
            close(m.SendChan)
        })

        m.wg.Wait()
    })
}
