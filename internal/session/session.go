package session

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/SrabanMondal/proxy-vpn/internal/pool"
)

type item struct {
	payload  []byte
	original []byte
}

type SessionContext struct {
	TargetConn net.Conn
	Window      map[uint32]item
	NextSeqID   uint32
	Signal      chan struct{}
	Quit        chan struct{}
	ClientAddr  *net.UDPAddr
	mu          sync.RWMutex
}

// Create new session for browser in client
func NewSession(browserConn net.Conn) *SessionContext {
	s := &SessionContext{
		TargetConn: browserConn,
		Window:      make(map[uint32]item),
		NextSeqID:   0,
		Signal:      make(chan struct{}, 1),
		Quit:        make(chan struct{}),
	}
	go s.runFlusher()
	return s
}

// Create a new session for client in server
func NewServerSession(targetConn net.Conn, clientAddr *net.UDPAddr) *SessionContext{
	s := &SessionContext{
		TargetConn: targetConn,
		Window:      make(map[uint32]item),
		NextSeqID:   0,
		Signal:      make(chan struct{}, 1),
		Quit:        make(chan struct{}),
		ClientAddr: clientAddr,
	}
	go s.runFlusher()
	return s
}

// Runs flusher as soon as session is created to detect incoming packets added in window
func (s *SessionContext) runFlusher() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.Signal:
			s.flush()
		case <-ticker.C:
			s.handleTimeout()
		case <-s.Quit:
			return
		}
	}
}

// Flushes the head of window
func (s *SessionContext) flush() {
	for {
		s.mu.RLock()
		next, ok := s.Window[s.NextSeqID]
		s.mu.RUnlock()

		if !ok {
			break
		}
         log.Printf(
			"[Session Window] Writing Payload to target Connection of (len=%d)", len(next.payload),
		)
		// Set write deadline
		_, err := s.TargetConn.Write(next.payload)
		if err != nil {
			s.Close()
			return
		}

		pool.Put(next.original)

		s.advance()
	}
}

// Slides window if no packet comes
func (s *SessionContext) handleTimeout() {
	s.mu.Lock()
	if len(s.Window) > 0 {
		_, exists := s.Window[s.NextSeqID]
		if !exists {
			s.NextSeqID++
		}
	}
	s.mu.Unlock()
	s.flush()
}

// Inserts packet payload in window
func (s *SessionContext) InsertPacket(seqID uint32, payload []byte, originalBuffer []byte) {
	s.mu.Lock()
	s.Window[seqID] = item{
		payload:  payload,
		original: originalBuffer,
	}
	s.mu.Unlock()

	select {
	case s.Signal <- struct{}{}:
	default:
	}
}

func (s *SessionContext) advance() {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Window, s.NextSeqID)
	s.NextSeqID++
}

// Closes the session
func (s *SessionContext) Close() {
	select {
	case <-s.Quit:
		return
	default:
		close(s.Quit)
		s.TargetConn.Close()
		s.mu.Lock()
		for _, itm := range s.Window {
			pool.Put(itm.original)
		}
		s.Window = nil
		s.mu.Unlock()
	}
}