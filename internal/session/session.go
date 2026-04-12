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

type sentItem struct {
	packet    []byte
	timestamp time.Time
}

const (
	defaultMaxSentPackets = 1024
	defaultSentRetention  = 5 * time.Second
	defaultNACKInterval   = 20 * time.Millisecond
	maxNACKBatch          = 16
	gapScanLimit          = 2048
)

type SessionContext struct {
	TargetConn net.Conn
	SessionID  uint32
	Window     map[uint32]item
	NextSeqID  uint32
	Signal     chan struct{}
	Quit       chan struct{}
	ClientAddr *net.UDPAddr
	NackSender func(sessionID uint32, missing []uint32)

	SentPackets    map[uint32]sentItem
	SentOrder      []uint32
	MaxSentPackets int
	SentRetention  time.Duration

	MissingSeq   map[uint32]time.Time
	NackInterval time.Duration

	mu     sync.RWMutex
	ready  bool
	closed bool
}

// Create new session for browser in client
func NewSession(browserConn net.Conn) *SessionContext {
	s := &SessionContext{
		TargetConn:     browserConn,
		Window:         make(map[uint32]item),
		NextSeqID:      0,
		Signal:         make(chan struct{}, 1),
		Quit:           make(chan struct{}),
		SentPackets:    make(map[uint32]sentItem),
		SentOrder:      make([]uint32, 0, defaultMaxSentPackets),
		MaxSentPackets: defaultMaxSentPackets,
		SentRetention:  defaultSentRetention,
		MissingSeq:     make(map[uint32]time.Time),
		NackInterval:   defaultNACKInterval,
		ready:          true,
	}
	go s.runFlusher()
	return s
}

// Create a new session for client in server
func NewServerSession(targetConn net.Conn, clientAddr *net.UDPAddr) *SessionContext {
	s := &SessionContext{
		TargetConn:     targetConn,
		Window:         make(map[uint32]item),
		NextSeqID:      0,
		Signal:         make(chan struct{}, 1),
		Quit:           make(chan struct{}),
		ClientAddr:     clientAddr,
		SentPackets:    make(map[uint32]sentItem),
		SentOrder:      make([]uint32, 0, defaultMaxSentPackets),
		MaxSentPackets: defaultMaxSentPackets,
		SentRetention:  defaultSentRetention,
		MissingSeq:     make(map[uint32]time.Time),
		NackInterval:   defaultNACKInterval,
		ready:          true,
	}
	go s.runFlusher()
	return s
}

// Create a pending session for server before target TCP dial is ready.
func NewPendingServerSession(clientAddr *net.UDPAddr) *SessionContext {
	s := &SessionContext{
		Window:         make(map[uint32]item),
		NextSeqID:      0,
		Signal:         make(chan struct{}, 1),
		Quit:           make(chan struct{}),
		ClientAddr:     clientAddr,
		SentPackets:    make(map[uint32]sentItem),
		SentOrder:      make([]uint32, 0, defaultMaxSentPackets),
		MaxSentPackets: defaultMaxSentPackets,
		SentRetention:  defaultSentRetention,
		MissingSeq:     make(map[uint32]time.Time),
		NackInterval:   defaultNACKInterval,
		ready:          false,
	}
	go s.runFlusher()
	return s
}

// Runs flusher as soon as session is created to detect incoming packets added in window
func (s *SessionContext) runFlusher() {
	ticker := time.NewTicker(s.NackInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.Signal:
			s.flush()
			s.retryMissingRequests()
			s.pruneSentPackets()
		case <-ticker.C:
			s.retryMissingRequests()
			s.pruneSentPackets()
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
			s.markMissingForCurrentGapLocked()
			s.mu.Unlock()
			return
		}

		delete(s.Window, s.NextSeqID)
		delete(s.MissingSeq, s.NextSeqID)
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

	if seqID > s.NextSeqID {
		s.markMissingRangeLocked(s.NextSeqID, seqID-1)
	}

	if _, exists := s.Window[seqID]; exists {
		s.mu.Unlock()
		pool.Put(originalBuffer)
		return
	}
	delete(s.MissingSeq, seqID)

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

func (s *SessionContext) SetSessionID(sessionID uint32) {
	s.mu.Lock()
	s.SessionID = sessionID
	s.mu.Unlock()
}

func (s *SessionContext) SetNackSender(sender func(sessionID uint32, missing []uint32)) {
	s.mu.Lock()
	s.NackSender = sender
	s.mu.Unlock()
}

func (s *SessionContext) TrackSentPacket(seqID uint32, packet []byte) {
	if len(packet) == 0 {
		return
	}

	cp := make([]byte, len(packet))
	copy(cp, packet)

	now := time.Now()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}

	if existing, ok := s.SentPackets[seqID]; ok {
		existing.packet = cp
		existing.timestamp = now
		s.SentPackets[seqID] = existing
		s.mu.Unlock()
		return
	}

	s.SentPackets[seqID] = sentItem{packet: cp, timestamp: now}
	s.SentOrder = append(s.SentOrder, seqID)
	s.evictSentPacketsLocked(now)
	s.mu.Unlock()
}

func (s *SessionContext) GetSentPacket(seqID uint32) ([]byte, bool) {
	s.mu.RLock()
	entry, ok := s.SentPackets[seqID]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}

	cp := make([]byte, len(entry.packet))
	copy(cp, entry.packet)
	return cp, true
}

func (s *SessionContext) retryMissingRequests() {
	now := time.Now()
	var sessionID uint32
	var missing []uint32
	var sender func(uint32, []uint32)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}

	s.markMissingForCurrentGapLocked()
	sessionID = s.SessionID
	sender = s.NackSender
	if sender != nil {
		missing = s.collectMissingForNACKLocked(now)
	}
	s.mu.Unlock()

	if sender != nil && len(missing) > 0 {
		sender(sessionID, missing)
	}
}

func (s *SessionContext) collectMissingForNACKLocked(now time.Time) []uint32 {
	if len(s.MissingSeq) == 0 {
		return nil
	}

	out := make([]uint32, 0, maxNACKBatch)
	start := s.NextSeqID
	for i := uint32(0); i <= gapScanLimit && len(out) < maxNACKBatch; i++ {
		seq := start + i
		last, ok := s.MissingSeq[seq]
		if !ok {
			if seq > start && len(out) > 0 {
				break
			}
			continue
		}

		if last.IsZero() || now.Sub(last) >= s.NackInterval {
			out = append(out, seq)
			s.MissingSeq[seq] = now
		}
	}

	return out
}

func (s *SessionContext) markMissingRangeLocked(from, to uint32) {
	if to < from {
		return
	}

	end := to
	if end > from+gapScanLimit {
		end = from + gapScanLimit
	}

	for seq := from; ; seq++ {
		if _, ok := s.Window[seq]; ok {
			if seq == end {
				break
			}
			continue
		}
		if _, ok := s.MissingSeq[seq]; !ok {
			s.MissingSeq[seq] = time.Time{}
		}
		if seq == end {
			break
		}
	}
}

func (s *SessionContext) markMissingForCurrentGapLocked() {
	if _, ok := s.Window[s.NextSeqID]; ok {
		delete(s.MissingSeq, s.NextSeqID)
		return
	}

	if s.hasBufferedFuturePacketLocked() {
		if _, ok := s.MissingSeq[s.NextSeqID]; !ok {
			s.MissingSeq[s.NextSeqID] = time.Time{}
		}
	}
}

func (s *SessionContext) hasBufferedFuturePacketLocked() bool {
	for seq := range s.Window {
		if seq > s.NextSeqID {
			return true
		}
	}
	return false
}

func (s *SessionContext) pruneSentPackets() {
	now := time.Now()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.evictSentPacketsLocked(now)
	s.mu.Unlock()
}

func (s *SessionContext) evictSentPacketsLocked(now time.Time) {
	for len(s.SentOrder) > 0 {
		oldestSeq := s.SentOrder[0]
		entry, ok := s.SentPackets[oldestSeq]
		if !ok {
			s.SentOrder = s.SentOrder[1:]
			continue
		}

		if len(s.SentPackets) <= s.MaxSentPackets && now.Sub(entry.timestamp) <= s.SentRetention {
			break
		}

		delete(s.SentPackets, oldestSeq)
		s.SentOrder = s.SentOrder[1:]
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
	s.NackSender = nil
	for seqID, itm := range s.Window {
		pool.Put(itm.original)
		delete(s.Window, seqID)
	}
	for seqID := range s.SentPackets {
		delete(s.SentPackets, seqID)
	}
	s.SentOrder = s.SentOrder[:0]
	for seqID := range s.MissingSeq {
		delete(s.MissingSeq, seqID)
	}
	close(s.Quit)
	s.mu.Unlock()

	if conn != nil {
		conn.Close()
	}
}
