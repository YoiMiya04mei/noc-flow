package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jdp-platform/noc-flow-collector/pkg/listener"
	"github.com/jdp-platform/noc-flow-collector/pkg/model"
	"github.com/jdp-platform/noc-flow-collector/pkg/simulator"
	"github.com/jdp-platform/noc-flow-collector/pkg/sink"
)

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return fallback
}

func main() {
	log.Println("==================================================")
	log.Println("JDP Route Intelligence - High-Rate Flow Collector")
	log.Println("==================================================")

	chHost := getEnv("CLICKHOUSE_HOST", "clickhouse")
	chPort := getEnvInt("CLICKHOUSE_PORT", 8123)
	chDB := getEnv("CLICKHOUSE_DB", "jdp_flow_analytics")
	chUser := getEnv("CLICKHOUSE_USER", "default")
	chPass := getEnv("CLICKHOUSE_PASSWORD", "clickhouse_dev_pass")

	netflowPort := getEnvInt("COLLECTOR_NETFLOW_PORT", 2055)
	sflowPort := getEnvInt("COLLECTOR_SFLOW_PORT", 6343)
	ipfixPort := getEnvInt("COLLECTOR_IPFIX_PORT", 4739)
	httpPort := getEnvInt("COLLECTOR_HTTP_PORT", 8081)
	batchSize := getEnvInt("COLLECTOR_BATCH_SIZE", 1000)
	demoMode := getEnv("DEMO_MODE", "true") == "true"

	metrics := &model.CollectorMetrics{}

	// Initialize ClickHouse Sink
	chSink := sink.NewClickHouseSink(
		chHost,
		chPort,
		chDB,
		chUser,
		chPass,
		batchSize,
		1*time.Second,
	)
	defer chSink.Stop()

	// Launch UDP Listeners
	nf5Listener := listener.NewUDPListener(
		fmt.Sprintf("0.0.0.0:%d", netflowPort),
		"netflow5",
		"POP-CGK-1",
		chSink,
		metrics,
		4,
		10000,
	)
	if err := nf5Listener.Start(); err != nil {
		log.Printf("[Warning] Failed to start NetFlow v5 listener: %v", err)
	}
	defer nf5Listener.Stop()

	sflowListener := listener.NewUDPListener(
		fmt.Sprintf("0.0.0.0:%d", sflowPort),
		"sflow5",
		"POP-CGK-1",
		chSink,
		metrics,
		4,
		10000,
	)
	if err := sflowListener.Start(); err != nil {
		log.Printf("[Warning] Failed to start sFlow listener: %v", err)
	}
	defer sflowListener.Stop()

	ipfixListener := listener.NewUDPListener(
		fmt.Sprintf("0.0.0.0:%d", ipfixPort),
		"ipfix",
		"POP-CGK-1",
		chSink,
		metrics,
		4,
		10000,
	)
	if err := ipfixListener.Start(); err != nil {
		log.Printf("[Warning] Failed to start IPFIX listener: %v", err)
	}
	defer ipfixListener.Stop()

	// Optional Demo Traffic Simulator
	if demoMode {
		log.Println("[Simulator] Starting Demo Traffic Simulator (explicitly labeled is_demo=1)...")
		sim := simulator.NewDemoTrafficSimulator(chSink, "POP-CGK-1")
		sim.Start(20) // 20 flows/sec baseline
		defer sim.Stop()
	}

	// Health and Metrics HTTP Server
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"service": "jdp-flow-collector",
		})
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"packets_received": metrics.PacketsReceived,
			"flows_parsed":     metrics.FlowsParsed,
			"parse_errors":     metrics.ParseErrors,
			"dropped_packets":  metrics.DroppedPackets,
		})
	})

	go func() {
		addr := fmt.Sprintf("0.0.0.0:%d", httpPort)
		log.Printf("[HTTP] Health and Metrics listening on http://%s", addr)
		if err := http.ListenAndServe(addr, nil); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[HTTP] Server failed: %v", err)
		}
	}()

	// Wait for OS shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("[Collector] Shutting down gracefully...")
}
