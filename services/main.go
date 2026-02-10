// NovaSec Cloud — Log Ingest Microservice
// DELIBERATELY INSECURE — no auth, no validation, no rate limiting
//
// Accepts POST /ingest with any JSON body and writes to PostgreSQL.
// NIST gaps: CM-6 (no hardening), SI-2 (no input validation), AC-2 (no auth)
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

// VULN: Hardcoded fallback credentials (IA-5 gap)
var (
	dbHost = getEnv("DB_HOST", "localhost")
	dbPort = getEnv("DB_PORT", "5432")
	dbName = getEnv("DB_NAME", "novasec")
	dbUser = getEnv("DB_USER", "novasec")
	dbPass = getEnv("DB_PASSWORD", "novasec_insecure_password_123")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type LogEvent struct {
	TenantID string `json:"tenant_id"`
	Level    string `json:"level"`
	Message  string `json:"message"`
	Source   string `json:"source"`
}

func main() {
	connStr := fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=disable",
		dbHost, dbPort, dbName, dbUser, dbPass,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Printf("WARN: Cannot connect to Postgres (%v), running in log-only mode", err)
	}

	// VULN: No auth header check on any endpoint (AC-2 gap)
	// VULN: No rate limiting (SI-2 gap)
	// VULN: No input validation — accepts any JSON (CM-6 gap)

	http.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}

		var event LogEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		// VULN: No input sanitization — SQL injection possible via tenant_id
		if db != nil {
			query := fmt.Sprintf(
				"INSERT INTO logs (tenant_id, level, message, source) VALUES ('%s', '%s', '%s', '%s')",
				event.TenantID, event.Level, event.Message, event.Source,
			)
			_, err := db.Exec(query)
			if err != nil {
				log.Printf("DB insert failed: %v", err)
			}
		}

		log.Printf("[%s] %s: %s (from %s)", event.TenantID, event.Level, event.Message, event.Source)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"status": "ingested"})
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "log-ingest"})
	})

	log.Println("NovaSec log-ingest listening on :9090")
	log.Fatal(http.ListenAndServe(":9090", nil))
}
