package sink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jdp-platform/noc-flow-collector/pkg/model"
)

type ClickHouseSink struct {
	host       string
	port       int
	database   string
	user       string
	password   string
	batchSize  int
	flushTimer time.Duration

	buffer []model.FlowRecord
	mu     sync.Mutex
	client *http.Client
	stopCh chan struct{}
}

func NewClickHouseSink(host string, port int, db, user, pass string, batchSize int, flushInterval time.Duration) *ClickHouseSink {
	s := &ClickHouseSink{
		host:       host,
		port:       port,
		database:   db,
		user:       user,
		password:   pass,
		batchSize:  batchSize,
		flushTimer: flushInterval,
		buffer:     make([]model.FlowRecord, 0, batchSize),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
	go s.runFlusher()
	return s
}

func (s *ClickHouseSink) Ingest(records []model.FlowRecord) {
	if len(records) == 0 {
		return
	}

	s.mu.Lock()
	s.buffer = append(s.buffer, records...)
	shouldFlush := len(s.buffer) >= s.batchSize
	s.mu.Unlock()

	if shouldFlush {
		s.Flush()
	}
}

func (s *ClickHouseSink) Flush() {
	s.mu.Lock()
	if len(s.buffer) == 0 {
		s.mu.Unlock()
		return
	}
	toSend := s.buffer
	s.buffer = make([]model.FlowRecord, 0, s.batchSize)
	s.mu.Unlock()

	go s.sendToClickHouse(toSend)
}

func (s *ClickHouseSink) sendToClickHouse(records []model.FlowRecord) {
	query := fmt.Sprintf("INSERT INTO %s.flow_records FORMAT JSONEachRow", s.database)
	endpoint := fmt.Sprintf("http://%s:%d/?query=%s", s.host, s.port, url.QueryEscape(query))

	var buf bytes.Buffer
	for _, rec := range records {
		// Format timestamp into ClickHouse DateTime64 string format: 2006-01-02 15:04:05.000
		type CHRecord struct {
			model.FlowRecord
			Timestamp string `json:"timestamp"`
		}
		chRec := CHRecord{
			FlowRecord: rec,
			Timestamp:  rec.Timestamp.Format("2006-01-02 15:04:05.000"),
		}
		line, err := json.Marshal(chRec)
		if err != nil {
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	req, err := http.NewRequest("POST", endpoint, &buf)
	if err != nil {
		log.Printf("[ClickHouseSink] Failed to create HTTP request: %v", err)
		return
	}
	if s.user != "" {
		req.SetBasicAuth(s.user, s.password)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("[ClickHouseSink] Error flushing %d records to ClickHouse: %v", len(records), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[ClickHouseSink] ClickHouse response error (status %d): %s", resp.StatusCode, string(body))
	}
}

func (s *ClickHouseSink) runFlusher() {
	ticker := time.NewTicker(s.flushTimer)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.Flush()
		case <-s.stopCh:
			s.Flush()
			return
		}
	}
}

func (s *ClickHouseSink) Stop() {
	close(s.stopCh)
}
