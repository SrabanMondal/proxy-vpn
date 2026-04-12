package session

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/SrabanMondal/proxy-vpn/internal/pool"
)

type item struct {
	payload    []byte
	original   []byte
	receivedAt time.Time
}

type SessionContext struct {
	TargetConn net.Conn
	Window     map[uint32]item
	NextSeqID  uint32
	Signal     chan struct{}
	Quit       chan struct{}
	ClientAddr *net.UDPAddr
	mu         sync.RWMutex
	ready      bool
	closed     bool
}

// Create new session for browser in client
func NewSession(browserConn net.Conn) *SessionContext {
	s := &SessionContext{
		TargetConn: browserConn,
		Window:     make(map[uint32]item),
		NextSeqID:  0,
		Signal:     make(chan struct{}, 1),
		Quit:       make(chan struct{}),
		ready:      true,
	}
	go s.runFlusher()
	return s
}

// Create a new session for client in server
func NewServerSession(targetConn net.Conn, clientAddr *net.UDPAddr) *SessionContext {
	s := &SessionContext{
		TargetConn: targetConn,
		Window:     make(map[uint32]item),
		NextSeqID:  0,
		Signal:     make(chan struct{}, 1),
		Quit:       make(chan struct{}),
		ClientAddr: clientAddr,
		ready:      true,
	}
	go s.runFlusher()
	return s
}

// Create a pending session for server before target TCP dial is ready.
func NewPendingServerSession(clientAddr *net.UDPAddr) *SessionContext {
	s := &SessionContext{
		Window:     make(map[uint32]item),
		NextSeqID:  0,
		Signal:     make(chan struct{}, 1),
		Quit:       make(chan struct{}),
		ClientAddr: clientAddr,
		ready:      false,
	}
	go s.runFlusher()
	return s
}

// Runs flusher as soon as session is created to detect incoming packets added in window
func (s *SessionContext) runFlusher() {
	for {
		select {
		case <-s.Signal:
			s.flush()
		case <-s.Quit:
			return
		}
	}
}

// Flushes the head of window
func (s *SessionContext) flush() {
	for {
		s.mu.Lock()
		if s.closed || !s.ready || s.TargetConn == nil {
			s.mu.Unlock()
			return
		}

		next, ok := s.Window[s.NextSeqID]
		if !ok {
			s.mu.Unlock()
			return
		}

		delete(s.Window, s.NextSeqID)
		s.NextSeqID++
		conn := s.TargetConn
		s.mu.Unlock()

		log.Printf("[Session Window] Writing Payload to target Connection of (len=%d)", len(next.payload))
		_, err := conn.Write(next.payload)
		if err != nil {
			pool.Put(next.original)
			s.Close()
			return
		}

		pool.Put(next.original)
	}
}

// Inserts packet payload in window
func (s *SessionContext) InsertPacket(seqID uint32, payload []byte, originalBuffer []byte) {
	select {
	case <-s.Quit:
		pool.Put(originalBuffer)
		return
	default:
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		pool.Put(originalBuffer)
		return
	}

	if s.Window == nil {
		s.mu.Unlock()
		pool.Put(originalBuffer)
		return
	}

	if seqID < s.NextSeqID {
		s.mu.Unlock()
		pool.Put(originalBuffer)
		return
	}

	if _, exists := s.Window[seqID]; exists {
		s.mu.Unlock()
		pool.Put(originalBuffer)
		return
	}

	s.Window[seqID] = item{
		payload:    payload,
		original:   originalBuffer,
		receivedAt: time.Now(),
	}
	s.mu.Unlock()

	select {
	case s.Signal <- struct{}{}:
	default:
	}
}

// SetTargetConn marks a pending session as ready and starts ordered flush.
func (s *SessionContext) SetTargetConn(conn net.Conn) {
	if conn == nil {
		return
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return
	}

	s.TargetConn = conn
	s.ready = true
	s.mu.Unlock()

	select {
	case s.Signal <- struct{}{}:
	default:
	}
}

// Closes the session
func (s *SessionContext) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}

	s.closed = true
	s.ready = false
	conn := s.TargetConn
	s.TargetConn = nil
	for seqID, itm := range s.Window {
		pool.Put(itm.original)
		delete(s.Window, seqID)
	}
	close(s.Quit)
	s.mu.Unlock()

	if conn != nil {
		conn.Close()
	}
}
