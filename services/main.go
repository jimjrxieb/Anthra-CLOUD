// Anthra Security Platform - Log Ingest Microservice
// Accepts log events from distributed agents and stores them centrally
//
// TLS terminated at ingress/ALB — internal traffic is pod-to-pod over cluster network
// See: infrastructure/ingress.yaml

package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

var (
	dbHost = getEnv("DB_HOST", "localhost")
	dbPort = getEnv("DB_PORT", "5432")
	dbName = getEnv("DB_NAME", "anthra")
	dbUser = getEnv("DB_USER", "anthra")
	dbPass = getEnvRequired("DB_PASSWORD")

	validLevels = map[string]bool{
		"DEBUG": true, "INFO": true, "WARN": true,
		"WARNING": true, "ERROR": true, "CRITICAL": true,
	}
)

const maxMessageLen = 4096

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvRequired(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Printf("WARNING: %s not set — DB writes will fail", key)
	}
	return v
}

// LogEvent represents an incoming log entry from agents
type LogEvent struct {
	TenantID string    `json:"tenant_id"`
	Level    string    `json:"level"`
	Message  string    `json:"message"`
	Source   string    `json:"source"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

func main() {
	sslMode := getEnv("DB_SSLMODE", "require")
	connStr := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		dbHost, dbPort, dbName, dbUser, dbPass, sslMode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("WARN: Cannot connect to Postgres (%v), running in log-only mode", err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", ingestHandler(db))
	mux.HandleFunc("/health", healthHandler)

	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")

	if certFile != "" && keyFile != "" {
		srv := &http.Server{
			Addr:    ":9090",
			Handler: mux,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		log.Println("Anthra log-ingest service listening on :9090 (TLS)")
		log.Fatal(srv.ListenAndServeTLS(certFile, keyFile))
	} else {
		// TLS terminated at ingress — plain HTTP for pod-to-pod traffic
		srv := &http.Server{
			Addr:         ":9090",
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		log.Println("Anthra log-ingest service listening on :9090 (TLS at ingress)")
		log.Fatal(srv.ListenAndServe())
	}
}

// ingestHandler processes incoming log events
func ingestHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		var event LogEvent
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		if err := decoder.Decode(&event); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Input validation
		event.Level = strings.ToUpper(event.Level)
		if !validLevels[event.Level] {
			http.Error(w, "Invalid log level", http.StatusBadRequest)
			return
		}
		if event.TenantID == "" || event.Source == "" {
			http.Error(w, "tenant_id and source are required", http.StatusBadRequest)
			return
		}
		if len(event.Message) > maxMessageLen {
			http.Error(w, "Message too long", http.StatusBadRequest)
			return
		}

		// Store in database
		if db != nil {
			_, err := db.Exec(
				"INSERT INTO logs (tenant_id, level, message, source, timestamp) VALUES ($1, $2, $3, $4, $5)",
				event.TenantID,
				event.Level,
				event.Message,
				event.Source,
				time.Now(),
			)
			if err != nil {
				log.Printf("DB insert failed: %v", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}
		}

		log.Printf("ingested tenant=%s level=%s source=%s", event.TenantID, event.Level, event.Source)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ingested",
			"tenant_id": event.TenantID,
			"timestamp": time.Now().Unix(),
		})
	}
}

// healthHandler provides service health status (unauthenticated — K8s probes)
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "anthra-log-ingest",
		"version": "1.1.0",
	})
}
