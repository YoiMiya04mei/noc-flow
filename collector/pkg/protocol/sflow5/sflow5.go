package sflow5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jdp-platform/noc-flow-collector/pkg/model"
)

const (
	HeaderSize = 28
	Version    = 5

	SampleTypeFlow         = 1
	SampleTypeCounter      = 2
	SampleTypeExpandedFlow = 3
)

var (
	ErrPacketTooShort = errors.New("packet shorter than sFlow header")
	ErrInvalidVersion = errors.New("invalid sFlow version, expected 5")
)

// Parse parses an sFlow v5 datagram and normalizes flow samples.
func Parse(payload []byte, exporterIP string, siteID string) ([]model.FlowRecord, error) {
	if len(payload) < HeaderSize {
		return nil, ErrPacketTooShort
	}

	version := binary.BigEndian.Uint32(payload[0:4])
	if version != Version {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidVersion, version)
	}

	samplesCount := binary.BigEndian.Uint32(payload[24:28])
	timestamp := time.Now().UTC()

	records := make([]model.FlowRecord, 0)
	offset := HeaderSize

	for s := 0; s < int(samplesCount) && offset+8 <= len(payload); s++ {
		sampleType := binary.BigEndian.Uint32(payload[offset : offset+4])
		sampleLen := int(binary.BigEndian.Uint32(payload[offset+4 : offset+8]))
		offset += 8

		if sampleLen <= 0 || offset+sampleLen > len(payload) {
			break
		}

		sampleData := payload[offset : offset+sampleLen]
		offset += sampleLen

		// Handle Standard Flow Sample (type 1) or Expanded Flow Sample (type 3)
		if (sampleType & 0x0FFF) == SampleTypeFlow && len(sampleData) >= 28 {
			samplingRate := binary.BigEndian.Uint32(sampleData[8:12])
			if samplingRate == 0 {
				samplingRate = 1
			}
			inputSNMP := binary.BigEndian.Uint32(sampleData[20:24])
			outputSNMP := binary.BigEndian.Uint32(sampleData[24:28])
			elementsCount := binary.BigEndian.Uint32(sampleData[28:32])

			eOffset := 32
			for e := 0; e < int(elementsCount) && eOffset+8 <= len(sampleData); e++ {
				elemFormat := binary.BigEndian.Uint32(sampleData[eOffset : eOffset+4])
				elemLen := int(binary.BigEndian.Uint32(sampleData[eOffset+4 : eOffset+8]))
				eOffset += 8

				if elemLen <= 0 || eOffset+elemLen > len(sampleData) {
					break
				}
				elemData := sampleData[eOffset : eOffset+elemLen]
				eOffset += elemLen

				// Raw packet header (format 1)
				if (elemFormat & 0x0FFF) == 1 && len(elemData) >= 16 {
					frameLen := binary.BigEndian.Uint32(elemData[4:8])
					hdrLen := int(binary.BigEndian.Uint32(elemData[12:16]))
					if hdrLen > 0 && 16+hdrLen <= len(elemData) {
						rawHdr := elemData[16 : 16+hdrLen]
						flow := decodeEthernetPacket(rawHdr, timestamp, exporterIP, siteID, samplingRate, inputSNMP, outputSNMP, frameLen)
						if flow != nil {
							records = append(records, *flow)
						}
					}
				}
			}
		}
	}

	return records, nil
}

func decodeEthernetPacket(pkt []byte, ts time.Time, exporterIP, siteID string, samplingRate, inSNMP, outSNMP, frameLen uint32) *model.FlowRecord {
	// Standard Ethernet header is 14 bytes: 6 dst MAC, 6 src MAC, 2 EtherType
	if len(pkt) < 14 {
		return nil
	}

	ethType := binary.BigEndian.Uint16(pkt[12:14])
	ipOffset := 14

	// Handle 802.1Q VLAN Tag (0x8100)
	if ethType == 0x8100 && len(pkt) >= 18 {
		ethType = binary.BigEndian.Uint16(pkt[16:18])
		ipOffset = 18
	}

	// IPv4 EtherType is 0x0800
	if ethType != 0x0800 || len(pkt) < ipOffset+20 {
		return nil
	}

	ipHdr := pkt[ipOffset:]
	ihl := int(ipHdr[0]&0x0F) * 4
	if len(ipHdr) < ihl {
		return nil
	}

	totalLen := binary.BigEndian.Uint16(ipHdr[2:4])
	if totalLen == 0 {
		totalLen = uint16(frameLen)
	}
	protocol := ipHdr[9]
	srcIP := net.IPv4(ipHdr[12], ipHdr[13], ipHdr[14], ipHdr[15]).String()
	dstIP := net.IPv4(ipHdr[16], ipHdr[17], ipHdr[18], ipHdr[19]).String()

	var srcPort, dstPort uint16
	var tcpFlags uint8

	if len(ipHdr) >= ihl+4 {
		l4Hdr := ipHdr[ihl:]
		if protocol == 6 { // TCP
			if len(l4Hdr) >= 14 {
				srcPort = binary.BigEndian.Uint16(l4Hdr[0:2])
				dstPort = binary.BigEndian.Uint16(l4Hdr[2:4])
				tcpFlags = l4Hdr[13]
			}
		} else if protocol == 17 { // UDP
			if len(l4Hdr) >= 4 {
				srcPort = binary.BigEndian.Uint16(l4Hdr[0:2])
				dstPort = binary.BigEndian.Uint16(l4Hdr[2:4])
			}
		}
	}

	bytes := uint64(totalLen) * uint64(samplingRate)
	packets := uint64(1) * uint64(samplingRate)

	return &model.FlowRecord{
		Timestamp:    ts,
		SiteID:       siteID,
		ExporterIP:   exporterIP,
		SrcIP:        srcIP,
		DstIP:        dstIP,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Protocol:     protocol,
		TCPFlags:     tcpFlags,
		Packets:      packets,
		Bytes:        bytes,
		InputSNMP:    inSNMP,
		OutputSNMP:   outSNMP,
		SamplingRate: samplingRate,
		FlowFormat:   "sflow5",
		IsDemo:       0,
	}
}
