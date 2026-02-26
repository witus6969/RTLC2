package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// tokenBucket implements the token bucket rate-limiting algorithm for a single IP.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// RateLimiter manages per-IP token buckets to enforce request rate limits.
type RateLimiter struct {
	buckets   map[string]*tokenBucket
	mu        sync.RWMutex
	maxTokens float64
	refillRate float64
}

// NewRateLimiter creates a RateLimiter with the given capacity and refill rate.
// maxTokens is the burst capacity; refillRate is tokens restored per second.
func NewRateLimiter(maxTokens, refillRate float64) *RateLimiter {
	rl := &RateLimiter{
		buckets:    make(map[string]*tokenBucket),
		maxTokens:  maxTokens,
		refillRate: refillRate,
	}
	go rl.cleanupLoop()
	return rl
}

// Allow checks whether the given IP has remaining tokens.
// It refills tokens based on elapsed time, then consumes one token.
// Returns true if the request is allowed, false if rate-limited.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.RLock()
	bucket, exists := rl.buckets[ip]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		// Double-check after acquiring write lock
		bucket, exists = rl.buckets[ip]
		if !exists {
			bucket = &tokenBucket{
				tokens:     rl.maxTokens,
				maxTokens:  rl.maxTokens,
				refillRate: rl.refillRate,
				lastRefill: time.Now(),
			}
			rl.buckets[ip] = bucket
		}
		rl.mu.Unlock()
	}

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens += elapsed * bucket.refillRate
	if bucket.tokens > bucket.maxTokens {
		bucket.tokens = bucket.maxTokens
	}
	bucket.lastRefill = now

	// Consume one token
	if bucket.tokens < 1.0 {
		return false
	}
	bucket.tokens -= 1.0
	return true
}

// cleanupLoop removes stale bucket entries every 5 minutes.
// An entry is considered stale if its tokens are fully replenished,
// meaning the IP has not made requests recently.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		for ip, bucket := range rl.buckets {
			bucket.mu.Lock()
			elapsed := time.Since(bucket.lastRefill).Seconds()
			projected := bucket.tokens + elapsed*bucket.refillRate
			if projected >= bucket.maxTokens {
				delete(rl.buckets, ip)
			}
			bucket.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

// rateLimitMiddleware returns HTTP middleware that enforces per-IP rate limits.
// When a client exceeds the rate limit, a 429 Too Many Requests response is returned.
func rateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			if !limiter.Allow(ip) {
				jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
