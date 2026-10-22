package netflow9

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/jdp-platform/noc-flow-collector/pkg/model"
)

const (
	HeaderSize = 20
	Version    = 9

	// NetFlow v9 Field Types (RFC 3954)
	FieldInBytes      = 1
	FieldInPkts       = 2
	FieldProtocol     = 4
	FieldTCPFlags     = 6
	FieldL4SrcPort    = 7
	FieldIPv4SrcAddr  = 8
	FieldInputSNMP    = 10
	FieldL4DstPort    = 11
	FieldIPv4DstAddr  = 12
	FieldOutputSNMP   = 14
	FieldIPv4NextHop  = 15
	FieldSrcAS        = 16
	FieldDstAS        = 17
)

var (
	ErrPacketTooShort = errors.New("packet shorter than NetFlow v9 header")
	ErrInvalidVersion = errors.New("invalid NetFlow version, expected 9")
)

type FieldSpec struct {
	Type   uint16
	Length uint16
}

type Template struct {
	TemplateID uint16
	FieldCount uint16
	Fields     []FieldSpec
	RecordLen  int
}

// TemplateStore caches templates per Exporter IP + SourceID
type TemplateStore struct {
	mu        sync.RWMutex
	templates map[string]*Template
}

func NewTemplateStore() *TemplateStore {
	return &TemplateStore{
		templates: make(map[string]*Template),
	}
}

var globalTemplates = NewTemplateStore()

func (s *TemplateStore) Set(key string, tmpl *Template) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.templates[key] = tmpl
}

func (s *TemplateStore) Get(key string) (*Template, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tmpl, ok := s.templates[key]
	return tmpl, ok
}

// Parse parses a NetFlow v9 packet, learns templates, and decodes data flowsets.
func Parse(payload []byte, exporterIP string, siteID string) ([]model.FlowRecord, error) {
	return ParseWithStore(payload, exporterIP, siteID, globalTemplates)
}

func ParseWithStore(payload []byte, exporterIP string, siteID string, store *TemplateStore) ([]model.FlowRecord, error) {
	if len(payload) < HeaderSize {
		return nil, ErrPacketTooShort
	}

	version := binary.BigEndian.Uint16(payload[0:2])
	if version != Version {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidVersion, version)
	}

	count := binary.BigEndian.Uint16(payload[2:4])
	unixSecs := binary.BigEndian.Uint32(payload[8:12])
	sourceID := binary.BigEndian.Uint32(payload[16:20])

	timestamp := time.Unix(int64(unixSecs), 0).UTC()
	if unixSecs == 0 {
		timestamp = time.Now().UTC()
	}

	records := make([]model.FlowRecord, 0)
	offset := HeaderSize

	for i := 0; i < int(count) && offset+4 <= len(payload); i++ {
		flowsetID := binary.BigEndian.Uint16(payload[offset : offset+2])
		flowsetLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))

		if flowsetLen < 4 || offset+flowsetLen > len(payload) {
			break
		}

		flowsetData := payload[offset+4 : offset+flowsetLen]

		if flowsetID == 0 {
			// Template FlowSet
			tmplOffset := 0
			for tmplOffset+4 <= len(flowsetData) {
				tmplID := binary.BigEndian.Uint16(flowsetData[tmplOffset : tmplOffset+2])
				fieldCount := binary.BigEndian.Uint16(flowsetData[tmplOffset+2 : tmplOffset+4])
				tmplOffset += 4

				if tmplOffset+int(fieldCount)*4 > len(flowsetData) {
					break
				}

				tmpl := &Template{
					TemplateID: tmplID,
					FieldCount: fieldCount,
					Fields:     make([]FieldSpec, 0, fieldCount),
				}

				recLen := 0
				for f := 0; f < int(fieldCount); f++ {
					fType := binary.BigEndian.Uint16(flowsetData[tmplOffset : tmplOffset+2])
					fLen := binary.BigEndian.Uint16(flowsetData[tmplOffset+2 : tmplOffset+4])
					tmplOffset += 4
					tmpl.Fields = append(tmpl.Fields, FieldSpec{Type: fType, Length: fLen})
					recLen += int(fLen)
				}
				tmpl.RecordLen = recLen

				key := fmt.Sprintf("%s:%d:%d", exporterIP, sourceID, tmplID)
				store.Set(key, tmpl)
			}
		} else if flowsetID >= 256 {
			// Data FlowSet
			key := fmt.Sprintf("%s:%d:%d", exporterIP, sourceID, flowsetID)
			tmpl, ok := store.Get(key)
			if ok && tmpl.RecordLen > 0 {
				dataOffset := 0
				for dataOffset+tmpl.RecordLen <= len(flowsetData) {
					recData := flowsetData[dataOffset : dataOffset+tmpl.RecordLen]
					flow := decodeV9Record(recData, tmpl, timestamp, exporterIP, siteID)
					records = append(records, flow)
					dataOffset += tmpl.RecordLen
				}
			}
		}

		offset += flowsetLen
	}

	return records, nil
}

func decodeV9Record(data []byte, tmpl *Template, ts time.Time, exporterIP, siteID string) model.FlowRecord {
	flow := model.FlowRecord{
		Timestamp:    ts,
		SiteID:       siteID,
		ExporterIP:   exporterIP,
		SamplingRate: 1,
		FlowFormat:   "netflow9",
	}

	offset := 0
	for _, f := range tmpl.Fields {
		fLen := int(f.Length)
		if offset+fLen > len(data) {
			break
		}
		val := data[offset : offset+fLen]

		switch f.Type {
		case FieldIPv4SrcAddr:
			if fLen == 4 {
				flow.SrcIP = net.IPv4(val[0], val[1], val[2], val[3]).String()
			}
		case FieldIPv4DstAddr:
			if fLen == 4 {
				flow.DstIP = net.IPv4(val[0], val[1], val[2], val[3]).String()
			}
		case FieldIPv4NextHop:
			if fLen == 4 {
				flow.NextHop = net.IPv4(val[0], val[1], val[2], val[3]).String()
			}
		case FieldL4SrcPort:
			if fLen == 2 {
				flow.SrcPort = binary.BigEndian.Uint16(val)
			}
		case FieldL4DstPort:
			if fLen == 2 {
				flow.DstPort = binary.BigEndian.Uint16(val)
			}
		case FieldProtocol:
			if fLen >= 1 {
				flow.Protocol = val[0]
			}
		case FieldTCPFlags:
			if fLen >= 1 {
				flow.TCPFlags = val[0]
			}
		case FieldInBytes:
			if fLen == 4 {
				flow.Bytes = uint64(binary.BigEndian.Uint32(val))
			} else if fLen == 8 {
				flow.Bytes = binary.BigEndian.Uint64(val)
			}
		case FieldInPkts:
			if fLen == 4 {
				flow.Packets = uint64(binary.BigEndian.Uint32(val))
			} else if fLen == 8 {
				flow.Packets = binary.BigEndian.Uint64(val)
			}
		case FieldInputSNMP:
			if fLen == 2 {
				flow.InputSNMP = uint32(binary.BigEndian.Uint16(val))
			} else if fLen == 4 {
				flow.InputSNMP = binary.BigEndian.Uint32(val)
			}
		case FieldOutputSNMP:
			if fLen == 2 {
				flow.OutputSNMP = uint32(binary.BigEndian.Uint16(val))
			} else if fLen == 4 {
				flow.OutputSNMP = binary.BigEndian.Uint32(val)
			}
		case FieldSrcAS:
			if fLen == 2 {
				flow.SrcAS = uint32(binary.BigEndian.Uint16(val))
			} else if fLen == 4 {
				flow.SrcAS = binary.BigEndian.Uint32(val)
			}
		case FieldDstAS:
			if fLen == 2 {
				flow.DstAS = uint32(binary.BigEndian.Uint16(val))
			} else if fLen == 4 {
				flow.DstAS = binary.BigEndian.Uint32(val)
			}
		}

		offset += fLen
	}

	return flow
}
