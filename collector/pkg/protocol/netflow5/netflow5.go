package netflow5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jdp-platform/noc-flow-collector/pkg/model"
)

const (
	HeaderSize = 24
	RecordSize = 48
	Version    = 5
)

var (
	ErrPacketTooShort = errors.New("packet is shorter than NetFlow v5 header")
	ErrInvalidVersion = errors.New("invalid NetFlow version, expected 5")
	ErrCountMismatch  = errors.New("packet data truncated for declared record count")
)

// Header represents NetFlow v5 24-byte packet header.
type Header struct {
	Version          uint16
	Count            uint16
	SysUptime        uint32
	UnixSecs         uint32
	UnixNanoSecs     uint32
	FlowSequence     uint32
	EngineType       uint8
	EngineID         uint8
	SamplingInterval uint16
}

// Parse parses a raw NetFlow v5 UDP packet and converts it to normalized FlowRecords.
func Parse(payload []byte, exporterIP string, siteID string) ([]model.FlowRecord, error) {
	if len(payload) < HeaderSize {
		return nil, ErrPacketTooShort
	}

	version := binary.BigEndian.Uint16(payload[0:2])
	if version != Version {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidVersion, version)
	}

	count := binary.BigEndian.Uint16(payload[2:4])
	unixSecs := binary.BigEndian.Uint32(payload[8:12])
	samplingInterval := binary.BigEndian.Uint16(payload[22:24]) & 0x3FFF
	if samplingInterval == 0 {
		samplingInterval = 1
	}

	expectedLen := HeaderSize + int(count)*RecordSize
	if len(payload) < expectedLen {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrCountMismatch, expectedLen, len(payload))
	}

	timestamp := time.Unix(int64(unixSecs), 0).UTC()
	if unixSecs == 0 {
		timestamp = time.Now().UTC()
	}

	records := make([]model.FlowRecord, 0, count)

	for i := 0; i < int(count); i++ {
		offset := HeaderSize + (i * RecordSize)
		rec := payload[offset : offset+RecordSize]

		srcIP := net.IPv4(rec[0], rec[1], rec[2], rec[3]).String()
		dstIP := net.IPv4(rec[4], rec[5], rec[6], rec[7]).String()
		nextHop := net.IPv4(rec[8], rec[9], rec[10], rec[11]).String()

		inputSNMP := binary.BigEndian.Uint16(rec[12:14])
		outputSNMP := binary.BigEndian.Uint16(rec[14:16])
		packets := binary.BigEndian.Uint32(rec[16:20])
		bytes := binary.BigEndian.Uint32(rec[20:24])

		srcPort := binary.BigEndian.Uint16(rec[32:34])
		dstPort := binary.BigEndian.Uint16(rec[34:36])
		tcpFlags := rec[37]
		protocol := rec[38]
		srcAS := binary.BigEndian.Uint16(rec[40:42])
		dstAS := binary.BigEndian.Uint16(rec[42:44])

		flow := model.FlowRecord{
			Timestamp:    timestamp,
			SiteID:       siteID,
			ExporterIP:   exporterIP,
			SrcIP:        srcIP,
			DstIP:        dstIP,
			SrcPort:      srcPort,
			DstPort:      dstPort,
			Protocol:     protocol,
			TCPFlags:     tcpFlags,
			Packets:      uint64(packets) * uint64(samplingInterval),
			Bytes:        uint64(bytes) * uint64(samplingInterval),
			InputSNMP:    uint32(inputSNMP),
			OutputSNMP:   uint32(outputSNMP),
			NextHop:      nextHop,
			SrcAS:        uint32(srcAS),
			DstAS:        uint32(dstAS),
			SamplingRate: uint32(samplingInterval),
			FlowFormat:   "netflow5",
			IsDemo:       0,
		}
		records = append(records, flow)
	}

	return records, nil
}
