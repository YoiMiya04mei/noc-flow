package model

import (
	"time"
)

// FlowRecord is the unified normalized schema for all flow telemetry.
type FlowRecord struct {
	Timestamp    time.Time `json:"timestamp"`
	SiteID       string    `json:"site_id"`
	ExporterIP   string    `json:"exporter_ip"`
	SrcIP        string    `json:"src_ip"`
	DstIP        string    `json:"dst_ip"`
	SrcPort      uint16    `json:"src_port"`
	DstPort      uint16    `json:"dst_port"`
	Protocol     uint8     `json:"protocol"`
	TCPFlags     uint8     `json:"tcp_flags"`
	Packets      uint64    `json:"packets"`
	Bytes        uint64    `json:"bytes"`
	InputSNMP    uint32    `json:"input_snmp"`
	OutputSNMP   uint32    `json:"output_snmp"`
	NextHop      string    `json:"next_hop"`
	SrcAS        uint32    `json:"src_as"`
	DstAS        uint32    `json:"dst_as"`
	SamplingRate uint32    `json:"sampling_rate"`
	FlowFormat   string    `json:"flow_format"`
	IsDemo       uint8     `json:"is_demo"` // 1 = demo, 0 = live
}

// CollectorMetrics holds atomic counters for collector observability.
type CollectorMetrics struct {
	PacketsReceived uint64
	FlowsParsed     uint64
	ParseErrors     uint64
	BytesIngested   uint64
	DroppedPackets  uint64
}
