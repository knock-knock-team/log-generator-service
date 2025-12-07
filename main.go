package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
)

var (
	agentLogEndpoint    string
	agentMetricEndpoint string
	agentAuthToken      string

	foundationAPIURL string
	foundationModel  string
	foundationAPIKey string

	logForwardCh = make(chan LogEntry, 100)

	// Metrics
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_connections",
			Help: "Number of active connections",
		},
	)

	processingErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "processing_errors_total",
			Help: "Total number of processing errors",
		},
	)
)

func init() {
	// Register metrics
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(activeConnections)
	prometheus.MustRegister(processingErrors)
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Service   string `json:"service"`
}

func logMessage(level, message string) {
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     level,
		Message:   message,
		Service:   "log-service",
	}
	log.Printf("[%s] %s - %s\n", entry.Level, entry.Timestamp, entry.Message)

	// Forward only ERROR, WARN and suspicious patterns to AI (reduce API load)
	shouldForward := level == "ERROR" || level == "WARN" ||
		strings.Contains(strings.ToLower(message), "timeout") ||
		strings.Contains(strings.ToLower(message), "failed") ||
		strings.Contains(strings.ToLower(message), "denied") ||
		strings.Contains(strings.ToLower(message), "unauthorized")

	if shouldForward && (agentLogEndpoint != "" || foundationAPIKey != "") {
		select {
		case logForwardCh <- entry:
		default:
			// Drop if channel is full to avoid blocking critical path
		}
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	activeConnections.Inc()
	defer activeConnections.Dec()

	logMessage("INFO", "Health check requested")

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","service":"log-service","timestamp":"%s"}`, time.Now().Format(time.RFC3339))

	duration := time.Since(start).Seconds()
	httpRequestDuration.WithLabelValues(r.Method, "/health").Observe(duration)
	httpRequestsTotal.WithLabelValues(r.Method, "/health", "200").Inc()
}

func generateLogsHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	activeConnections.Inc()
	defer activeConnections.Dec()

	levels := []string{"INFO", "WARN", "ERROR", "DEBUG"}
	messages := map[string][]string{
		"INFO":  {"User authentication successful", "API request processed", "Background job completed"},
		"WARN":  {"Cache miss for key", "Slow query detected (>500ms)", "Rate limit approaching"},
		"ERROR": {"Database connection timeout", "Failed to parse JSON payload", "Memory allocation failed", "Deadlock detected in transaction"},
		"DEBUG": {"Configuration reloaded", "Request headers validated"},
	}

	count := rand.Intn(5) + 1
	for i := 0; i < count; i++ {
		level := levels[rand.Intn(len(levels))]
		msgs := messages[level]
		message := msgs[rand.Intn(len(msgs))]
		logMessage(level, message)

		if level == "ERROR" {
			processingErrors.Inc()
		}
		time.Sleep(100 * time.Millisecond)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"generated_logs":%d,"timestamp":"%s"}`, count, time.Now().Format(time.RFC3339))

	duration := time.Since(start).Seconds()
	httpRequestDuration.WithLabelValues(r.Method, "/generate-logs").Observe(duration)
	httpRequestsTotal.WithLabelValues(r.Method, "/generate-logs", "200").Inc()

	logMessage("INFO", fmt.Sprintf("Generated %d log entries", count))
}

func simulateTrafficHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	activeConnections.Inc()
	defer activeConnections.Dec()

	logMessage("INFO", "Starting traffic simulation")

	// Simulate varying load
	duration := rand.Intn(500) + 100
	time.Sleep(time.Duration(duration) * time.Millisecond)

	statusCode := http.StatusOK
	if rand.Float32() < 0.1 { // 10% error rate
		statusCode = http.StatusInternalServerError
		processingErrors.Inc()
		logMessage("ERROR", "Simulated error occurred")
	}

	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `{"status":%d,"duration_ms":%d}`, statusCode, duration)

	requestDuration := time.Since(start).Seconds()
	httpRequestDuration.WithLabelValues(r.Method, "/simulate").Observe(requestDuration)
	httpRequestsTotal.WithLabelValues(r.Method, "/simulate", fmt.Sprintf("%d", statusCode)).Inc()
}

func backgroundMetricsGenerator() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Simulate changing active connections
		connections := float64(rand.Intn(100))
		activeConnections.Set(connections)

		logMessage("DEBUG", fmt.Sprintf("Background metrics update: %d active connections", int(connections)))
	}
}

// autoLogGenerator periodically generates random logs for testing AI analysis
func autoLogGenerator(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		// Default to 8 seconds if not configured - generates frequent error/warn logs
		interval = 8 * time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		log.Printf("[INFO] Auto log generation enabled: every %s (ERROR/WARN focused)", interval)

		// Weighted towards ERROR and WARN for AI analysis
		levels := []string{"ERROR", "ERROR", "ERROR", "WARN", "WARN", "INFO"}
		messages := map[string][]string{
			"INFO":  {"User authentication successful", "API request processed"},
			"WARN":  {"Cache miss for key", "Slow query detected (>500ms)", "Rate limit approaching", "Connection pool exhausted"},
			"ERROR": {"Database connection timeout", "Failed to parse JSON payload", "Memory allocation failed", "Deadlock detected in transaction", "Authentication failed", "Service unavailable", "Request timeout exceeded"},
		}

		for {
			select {
			case <-ticker.C:
				// Generate 2-4 random logs each interval
				count := rand.Intn(3) + 2
				for i := 0; i < count; i++ {
					level := levels[rand.Intn(len(levels))]
					msgs := messages[level]
					message := msgs[rand.Intn(len(msgs))]
					logMessage(level, message)
					time.Sleep(80 * time.Millisecond)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// startLogForwarder ships log entries to the configured AI agent endpoint.
func startLogForwarder(ctx context.Context, client *http.Client, endpoint string, foundationEnabled bool, foundationSend func(context.Context, string)) {
	go func() {
		for {
			select {
			case entry := <-logForwardCh:
				payload, err := json.Marshal(entry)
				if err != nil {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				if agentAuthToken != "" {
					req.Header.Set("Authorization", "Bearer "+agentAuthToken)
				}
				_, _ = client.Do(req) // best effort; ignore response

				if foundationEnabled && foundationSend != nil {
					msg := fmt.Sprintf("LOG %s %s %s", entry.Level, entry.Timestamp, entry.Message)
					foundationSend(ctx, msg)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// startMetricPusher periodically gathers Prometheus metrics and forwards them as text exposition format.
func startMetricPusher(ctx context.Context, client *http.Client, endpoint string, interval time.Duration, foundationEnabled bool, foundationSend func(context.Context, string)) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				mfs, err := prometheus.DefaultGatherer.Gather()
				if err != nil {
					continue
				}

				var buf bytes.Buffer
				encoder := expfmt.NewEncoder(&buf, expfmt.FmtText)
				for _, mf := range mfs {
					if err := encoder.Encode(mf); err != nil {
						break
					}
				}

				// Send to webhook if configured
				if endpoint != "" {
					req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf.Bytes()))
					if err != nil {
						continue
					}
					req.Header.Set("Content-Type", string(expfmt.FmtText))
					if agentAuthToken != "" {
						req.Header.Set("Authorization", "Bearer "+agentAuthToken)
					}
					_, _ = client.Do(req) // best effort
				}

				// Send to Foundation API only if anomalies detected (high errors, low connections)
				if foundationEnabled && foundationSend != nil {
					metricsPayload := buf.String()
					hasAnomaly := strings.Contains(metricsPayload, "processing_errors_total") &&
						(strings.Contains(metricsPayload, "processing_errors_total 1") ||
							strings.Contains(metricsPayload, "active_connections 0"))

					if hasAnomaly {
						if len(metricsPayload) > 16000 {
							metricsPayload = metricsPayload[:16000]
						}
						foundationSend(ctx, "METRICS ANOMALY DETECTED\n"+metricsPayload)
					}
				}

			case <-ctx.Done():
				return
			}
		}
	}()
}

// sendToFoundation posts a chat-style message to the foundation models API (OpenAI-compatible schema).
func sendToFoundation(ctx context.Context, client *http.Client, apiURL, model, apiKey, content string) {
	base := strings.TrimRight(apiURL, "/")
	endpoint := base + "/chat/completions"

	log.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("📤 [AI REQUEST] %s", content)
	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	systemPrompt := `Ты — DevOps-ассистент для анализа телеметрии Go-сервиса.

**Твоя задача:**
- Для ERROR/WARN: анализируй причину, предлагай решение (макс. 2 предложения)
- Для INFO/DEBUG: кратко подтверждай приём (1 фраза)
- Для METRICS: если есть аномалии (high errors, low connections) — предупреди, иначе "OK"

**Формат ответа:** краткий, по делу, на русском.`

	body := map[string]interface{}{
		"model":       model,
		"max_tokens":  128,
		"temperature": 0.3,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": content},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[WARN] Foundation API request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[WARN] Foundation API returned status %d", resp.StatusCode)
		return
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[WARN] Foundation API response decode error: %v", err)
		return
	}

	// Extract and log the assistant's reply
	if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if msg, ok := choice["message"].(map[string]interface{}); ok {
				if content, ok := msg["content"].(string); ok {
					log.Printf("💬 [AI RESPONSE] %s", content)
					log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
				}
			}
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())

	// Set UTF-8 encoding for proper Cyrillic display
	log.SetFlags(log.LstdFlags | log.LUTC)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	agentLogEndpoint = os.Getenv("AGENT_LOG_ENDPOINT")
	agentMetricEndpoint = os.Getenv("AGENT_METRIC_ENDPOINT")
	agentAuthToken = os.Getenv("AGENT_AUTH_TOKEN")

	foundationAPIURL = os.Getenv("FOUNDATION_API_URL")
	if foundationAPIURL == "" {
		foundationAPIURL = "https://foundation-models.api.cloud.ru/v1"
	}

	foundationModel = os.Getenv("FOUNDATION_MODEL")
	if foundationModel == "" {
		foundationModel = "ai-sage/GigaChat3-10B-A1.8B"
	}

	foundationAPIKey = os.Getenv("FOUNDATION_API_KEY")
	foundationEnabled := foundationAPIKey != ""

	metricPushInterval := 5 * time.Minute // Default 5 minutes to reduce API load
	if val := os.Getenv("AGENT_METRIC_INTERVAL"); val != "" {
		if parsed, err := time.ParseDuration(val); err == nil {
			metricPushInterval = parsed
		}
	}

	autoLogInterval := time.Duration(0)
	if val := os.Getenv("AUTO_LOG_INTERVAL"); val != "" {
		if parsed, err := time.ParseDuration(val); err == nil {
			autoLogInterval = parsed
		}
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}

	foundationSend := func(ctx context.Context, content string) {
		if foundationEnabled {
			sendToFoundation(ctx, httpClient, foundationAPIURL, foundationModel, foundationAPIKey, content)
		}
	}

	if foundationEnabled {
		logMessage("INFO", fmt.Sprintf("Foundation API forwarding включен -> %s (model=%s)", foundationAPIURL, foundationModel))
	}

	// Start log forwarder if either webhook or Foundation API is configured
	if agentLogEndpoint != "" || foundationEnabled {
		if agentLogEndpoint != "" {
			logMessage("INFO", fmt.Sprintf("AI agent log forwarding enabled -> %s", agentLogEndpoint))
		}
		startLogForwarder(ctx, httpClient, agentLogEndpoint, foundationEnabled, foundationSend)
	}

	// Start metric pusher if either webhook or Foundation API is configured
	if agentMetricEndpoint != "" || foundationEnabled {
		if agentMetricEndpoint != "" {
			logMessage("INFO", fmt.Sprintf("AI agent metric forwarding enabled -> %s (every %s)", agentMetricEndpoint, metricPushInterval))
		}
		startMetricPusher(ctx, httpClient, agentMetricEndpoint, metricPushInterval, foundationEnabled, foundationSend)
	}

	// Start background metrics generator
	go backgroundMetricsGenerator()

	// Start auto log generator if configured
	autoLogGenerator(ctx, autoLogInterval)

	// Setup HTTP handlers
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/generate-logs", generateLogsHandler)
	http.HandleFunc("/simulate", simulateTrafficHandler)
	http.Handle("/metrics", promhttp.Handler())

	logMessage("INFO", fmt.Sprintf("Starting log-service on port %s", port))
	logMessage("INFO", "Endpoints: /health, /generate-logs, /simulate, /metrics")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		logMessage("ERROR", fmt.Sprintf("Server failed to start: %v", err))
		os.Exit(1)
	}
}
