package main

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type APIServer struct {
	addr string
}

func NewAPIServer(addr string) *APIServer {
	return &APIServer{
		addr: addr,
	}
}

func (s *APIServer) Run() error {
	routerV1 := http.NewServeMux()
	routerV2 := http.NewServeMux()

	routerV1.HandleFunc("GET /users/{userID}", func(w http.ResponseWriter, r *http.Request) {
		userID := r.PathValue("userID")
		w.Write([]byte("User ID: " + userID + " API V1"))
	})

	routerV2.HandleFunc("GET /users/{userID}", func(w http.ResponseWriter, r *http.Request) {
		userID := r.PathValue("userID")
		w.Write([]byte("User ID: " + userID + " API V2"))
	})

	adminRouter := http.NewServeMux()
	adminRouter.Handle("/api/v1/", http.StripPrefix("/api/v1", routerV1))
	adminRouter.Handle("/api/v2/", http.StripPrefix("/api/v2", routerV2))

	middlewareChain := MiddlewareChain(
		RequestLoggerMiddleware,
		RequireAuthMiddleware,
		ThrottlingMiddleware(5*time.Second),      // One request per second
		RateLimitingMiddleware(3, 1*time.Minute), // Five request per minute
	)

	server := http.Server{
		Addr:    s.addr,
		Handler: middlewareChain(adminRouter),
	}

	log.Printf("Server has started %s", s.addr)

	return server.ListenAndServe()
}

func RequestLoggerMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("method %s, path: %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	}
}

func RequireAuthMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")

		if token != "Bearer token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

type Middleware func(http.Handler) http.HandlerFunc

func MiddlewareChain(middleware ...Middleware) Middleware {
	return func(next http.Handler) http.HandlerFunc {
		for i := len(middleware) - 1; i >= 0; i-- {
			next = middleware[i](next)
		}

		return next.ServeHTTP
	}
}

var lastRequestTime = make(map[string]time.Time)
var mu sync.Mutex

func ThrottlingMiddleware(limit time.Duration) Middleware {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			path := r.URL.Path
			if !strings.Contains(path, "/users/") {
				http.Error(w, "Invalid URL format", http.StatusBadRequest)
				return
			}

			userID := path[len("/users/"):]
			if userID == "" {
				http.Error(w, "User ID is required", http.StatusBadRequest)
				return
			}

			mu.Lock()
			defer mu.Unlock()

			lastTime, exists := lastRequestTime[userID]
			if exists && time.Since(lastTime) < limit {
				http.Error(w, "Too Many Requests [Throttling Middleware Block Request]", http.StatusTooManyRequests)
				return
			}

			lastRequestTime[userID] = time.Now()

			next.ServeHTTP(w, r)
		}
	}
}

func RateLimitingMiddleware(maxRequests int, duration time.Duration) Middleware {
	var requestCounts sync.Map

	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			path := r.URL.Path
			if !strings.Contains(path, "/users/") {
				http.Error(w, "Invalid URL format", http.StatusBadRequest)
				return
			}

			userID := path[len("/users/"):]
			if userID == "" {
				http.Error(w, "User ID is required", http.StatusBadRequest)
				return
			}

			value, _ := requestCounts.LoadOrStore(userID, &rateLimiter{
				requestCount: 0,
				resetTime:    time.Now().Add(duration),
				mu:           sync.Mutex{},
			})

			limiter := value.(*rateLimiter)

			limiter.mu.Lock()
			defer limiter.mu.Unlock()

			if time.Now().After(limiter.resetTime) {
				limiter.requestCount = 0
				limiter.resetTime = time.Now().Add(duration)
			}

			if limiter.requestCount >= maxRequests {
				http.Error(w, "Too Many Requests [Rate Limiting Middleware Block Request]", http.StatusTooManyRequests)
				return
			}

			limiter.requestCount++
			next.ServeHTTP(w, r)
		}
	}
}

type rateLimiter struct {
	requestCount int
	resetTime    time.Time
	mu           sync.Mutex
}
