// TokenBucket implements a simple token bucket for rate limiting.
package server

import (
	"sync"
	"time"
)

type TokenBucket struct {
	rate      float64   // tokens per second
	burst     float64   // maximum bucket capacity
	tokens    float64
	lastCheck time.Time
	mu        sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(rate, burst float64) *TokenBucket {
	return &TokenBucket{
		rate:      rate,
		burst:     burst,
		tokens:    burst,
		lastCheck: time.Now(),
	}
}

// Wait blocks until tokensToConsume are available
func (tb *TokenBucket) Wait(tokensToConsume int) {
	tb.mu.Lock()
	needed := float64(tokensToConsume)
	
	for tb.tokens < needed {
		// Calculate how much time to wait for tokens to refill
		missing := needed - tb.tokens
		waitDuration := time.Duration(missing/tb.rate * float64(time.Second))
		
		tb.mu.Unlock()
		time.Sleep(waitDuration) // Sleep exactly the amount of time needed
		tb.mu.Lock()
		
		// Refill after sleep
		now := time.Now()
		tb.tokens += now.Sub(tb.lastCheck).Seconds() * tb.rate
		if tb.tokens > tb.burst {
			tb.tokens = tb.burst
		}
		tb.lastCheck = now
	}

	tb.tokens -= needed
	tb.mu.Unlock()
}

// TryConsume attempts to consume tokens without blocking
func (tb *TokenBucket) TryConsume(tokensToConsume int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.tokens >= float64(tokensToConsume) {
		tb.tokens -= float64(tokensToConsume)
		return true
	}
	return false
}
