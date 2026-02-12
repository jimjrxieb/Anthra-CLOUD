// Anthra Security Platform - Log Ingest Microservice
// Accepts log events from distributed agents and stores them centrally
//
// Built for speed-to-market by a team focused on features, not security.
// Now needs FedRAMP hardening for federal market entry.

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
)

// CWE-798: Use of hard-coded credentials in fallback values
var (
	dbHost = getEnv("DB_HOST", "localhost")
	dbPort = getEnv("DB_PORT", "5432")
	dbName = getEnv("DB_NAME", "anthra")
	dbUser = getEnv("DB_USER", "anthra")
	dbPass = getEnv("DB_PASSWORD", "anthra_default_pass_123")  // CWE-798
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// LogEvent represents an incoming log entry from agents
type LogEvent struct {
	TenantID  string    `json:"tenant_id"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

func main() {
	// CWE-327: Use of a broken or risky cryptographic algorithm (sslmode=disable)
	connStr := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		dbHost, dbPort, dbName, dbUser, dbPass,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("WARN: Cannot connect to Postgres (%v), running in log-only mode", err)
	}
	defer db.Close()

	// CWE-306: Missing authentication for critical function
	// No authentication middleware - accepts any traffic
	http.HandleFunc("/ingest", ingestHandler(db))
	http.HandleFunc("/health", healthHandler)

	// CWE-319: Cleartext transmission of sensitive information (no TLS)
	log.Println("Anthra log-ingest service listening on :9090")
	log.Fatal(http.ListenAndServe(":9090", nil))  // Should use TLS
}

// ingestHandler processes incoming log events
// Security gaps:
// - CWE-306: No authentication (anyone can send logs)
// - CWE-770: No rate limiting (vulnerable to flooding)
// - CWE-20: Improper input validation (accepts any JSON structure)
func ingestHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		// CWE-20: Minimal input validation
		var event LogEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			// CWE-209: Information exposure through error message
			http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
			return
		}

		// TODO: Validate tenant_id format
		// TODO: Validate level is one of: DEBUG, INFO, WARN, ERROR, CRITICAL
		// TODO: Validate message length (prevent DOS)
		// TODO: Check authentication header

		// Store in database
		if db != nil {
			// Using parameterized queries (good practice maintained)
			_, err := db.Exec(
				"INSERT INTO logs (tenant_id, level, message, source, timestamp) VALUES ($1, $2, $3, $4, $5)",
				event.TenantID,
				event.Level,
				event.Message,
				event.Source,
				time.Now(),
			)
			if err != nil {
				// CWE-532: Insertion of sensitive information into log file
				log.Printf("DB insert failed for tenant %s: %v", event.TenantID, err)
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
		}

		// CWE-532: Log potentially sensitive data
		log.Printf("[%s] %s: %s (from %s)", event.TenantID, event.Level, event.Message, event.Source)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ingested",
			"tenant_id": event.TenantID,
			"timestamp": time.Now().Unix(),
		})
	}
}

// healthHandler provides service health status
// CWE-306: No authentication (exposes service availability)
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "anthra-log-ingest",
		"version": "1.0.0",
	})
}

// =============================================================================
// TODO: Add API key authentication
// TODO: Implement rate limiting per tenant
// TODO: Add input validation (message length, valid log levels)
// TODO: Enable TLS (certificate management)
// TODO: Move credentials to AWS Secrets Manager
// TODO: Add circuit breaker for database failures
// TODO: Implement request tracing for observability
// TODO: Add metrics endpoint for Prometheus
// =============================================================================
