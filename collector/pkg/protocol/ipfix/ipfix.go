package ipfix

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
	HeaderSize = 16
	Version    = 10 // IPFIX / NetFlow v10

	FieldOctetDeltaCount    = 1
	FieldPacketDeltaCount   = 2
	FieldProtocolIdentifier = 4
	FieldTCPControlBits     = 6
	FieldSourceTransportPort = 7
	FieldSourceIPv4Address  = 8
	FieldIngressInterface   = 10
	FieldDestinationTransportPort = 11
	FieldDestinationIPv4Address = 12
	FieldEgressInterface    = 14
	FieldIPNextHopIPv4Address = 15
	FieldBgpSourceAsNumber  = 16
	FieldBgpDestinationAsNumber = 17
)

var (
	ErrPacketTooShort = errors.New("packet shorter than IPFIX header")
	ErrInvalidVersion = errors.New("invalid IPFIX version, expected 10")
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

// Parse parses an IPFIX message and normalizes to FlowRecord.
func Parse(payload []byte, exporterIP string, siteID string) ([]model.FlowRecord, error) {
	if len(payload) < HeaderSize {
		return nil, ErrPacketTooShort
	}

	version := binary.BigEndian.Uint16(payload[0:2])
	if version != Version {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidVersion, version)
	}

	msgLen := int(binary.BigEndian.Uint16(payload[2:4]))
	if msgLen > len(payload) {
		msgLen = len(payload)
	}

	exportTime := binary.BigEndian.Uint32(payload[4:8])
	obsDomainID := binary.BigEndian.Uint32(payload[12:16])

	timestamp := time.Unix(int64(exportTime), 0).UTC()
	if exportTime == 0 {
		timestamp = time.Now().UTC()
	}

	records := make([]model.FlowRecord, 0)
	offset := HeaderSize

	for offset+4 <= msgLen {
		setID := binary.BigEndian.Uint16(payload[offset : offset+2])
		setLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))

		if setLen < 4 || offset+setLen > msgLen {
			break
		}

		setData := payload[offset+4 : offset+setLen]

		if setID == 2 {
			// Template Set
			tOffset := 0
			for tOffset+4 <= len(setData) {
				tmplID := binary.BigEndian.Uint16(setData[tOffset : tOffset+2])
				fieldCount := binary.BigEndian.Uint16(setData[tOffset+2 : tOffset+4])
				tOffset += 4

				tmpl := &Template{
					TemplateID: tmplID,
					FieldCount: fieldCount,
					Fields:     make([]FieldSpec, 0, fieldCount),
				}

				recLen := 0
				for f := 0; f < int(fieldCount); f++ {
					if tOffset+4 > len(setData) {
						break
					}
					fType := binary.BigEndian.Uint16(setData[tOffset : tOffset+2])
					fLen := binary.BigEndian.Uint16(setData[tOffset+2 : tOffset+4])
					tOffset += 4

					// Mask enterprise bit if present
					if fType&0x8000 != 0 {
						fType = fType & 0x7FFF
						tOffset += 4 // Enterprise number
					}

					tmpl.Fields = append(tmpl.Fields, FieldSpec{Type: fType, Length: fLen})
					recLen += int(fLen)
				}
				tmpl.RecordLen = recLen

				key := fmt.Sprintf("%s:%d:%d", exporterIP, obsDomainID, tmplID)
				globalTemplates.mu.Lock()
				globalTemplates.templates[key] = tmpl
				globalTemplates.mu.Unlock()
			}
		} else if setID >= 256 {
			// Data Set
			key := fmt.Sprintf("%s:%d:%d", exporterIP, obsDomainID, setID)
			globalTemplates.mu.RLock()
			tmpl, ok := globalTemplates.templates[key]
			globalTemplates.mu.RUnlock()

			if ok && tmpl.RecordLen > 0 {
				dOffset := 0
				for dOffset+tmpl.RecordLen <= len(setData) {
					recData := setData[dOffset : dOffset+tmpl.RecordLen]
					flow := decodeIPFIXRecord(recData, tmpl, timestamp, exporterIP, siteID)
					records = append(records, flow)
					dOffset += tmpl.RecordLen
				}
			}
		}

		offset += setLen
	}

	return records, nil
}

func decodeIPFIXRecord(data []byte, tmpl *Template, ts time.Time, exporterIP, siteID string) model.FlowRecord {
	flow := model.FlowRecord{
		Timestamp:    ts,
		SiteID:       siteID,
		ExporterIP:   exporterIP,
		SamplingRate: 1,
		FlowFormat:   "ipfix",
	}

	offset := 0
	for _, f := range tmpl.Fields {
		fLen := int(f.Length)
		if offset+fLen > len(data) {
			break
		}
		val := data[offset : offset+fLen]

		switch f.Type {
		case FieldSourceIPv4Address:
			if fLen == 4 {
				flow.SrcIP = net.IPv4(val[0], val[1], val[2], val[3]).String()
			}
		case FieldDestinationIPv4Address:
			if fLen == 4 {
				flow.DstIP = net.IPv4(val[0], val[1], val[2], val[3]).String()
			}
		case FieldIPNextHopIPv4Address:
			if fLen == 4 {
				flow.NextHop = net.IPv4(val[0], val[1], val[2], val[3]).String()
			}
		case FieldSourceTransportPort:
			if fLen == 2 {
				flow.SrcPort = binary.BigEndian.Uint16(val)
			}
		case FieldDestinationTransportPort:
			if fLen == 2 {
				flow.DstPort = binary.BigEndian.Uint16(val)
			}
		case FieldProtocolIdentifier:
			if fLen >= 1 {
				flow.Protocol = val[0]
			}
		case FieldTCPControlBits:
			if fLen >= 1 {
				flow.TCPFlags = val[0]
			}
		case FieldOctetDeltaCount:
			if fLen == 4 {
				flow.Bytes = uint64(binary.BigEndian.Uint32(val))
			} else if fLen == 8 {
				flow.Bytes = binary.BigEndian.Uint64(val)
			}
		case FieldPacketDeltaCount:
			if fLen == 4 {
				flow.Packets = uint64(binary.BigEndian.Uint32(val))
			} else if fLen == 8 {
				flow.Packets = binary.BigEndian.Uint64(val)
			}
		case FieldIngressInterface:
			if fLen == 2 {
				flow.InputSNMP = uint32(binary.BigEndian.Uint16(val))
			} else if fLen == 4 {
				flow.InputSNMP = binary.BigEndian.Uint32(val)
			}
		case FieldEgressInterface:
			if fLen == 2 {
				flow.OutputSNMP = uint32(binary.BigEndian.Uint16(val))
			} else if fLen == 4 {
				flow.OutputSNMP = binary.BigEndian.Uint32(val)
			}
		case FieldBgpSourceAsNumber:
			if fLen == 2 {
				flow.SrcAS = uint32(binary.BigEndian.Uint16(val))
			} else if fLen == 4 {
				flow.SrcAS = binary.BigEndian.Uint32(val)
			}
		case FieldBgpDestinationAsNumber:
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
