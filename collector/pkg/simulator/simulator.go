package simulator

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/jdp-platform/noc-flow-collector/pkg/model"
	"github.com/jdp-platform/noc-flow-collector/pkg/sink"
)

// GenerateNetFlow5Packet builds a valid binary NetFlow v5 datagram.
func GenerateNetFlow5Packet(recordCount int) []byte {
	if recordCount <= 0 || recordCount > 30 {
		recordCount = 10
	}

	totalLen := 24 + (recordCount * 48)
	buf := make([]byte, totalLen)

	// Header (24 bytes)
	binary.BigEndian.PutUint16(buf[0:2], 5)                     // Version 5
	binary.BigEndian.PutUint16(buf[2:4], uint16(recordCount))  // Count
	binary.BigEndian.PutUint32(buf[4:8], 12345678)             // SysUptime
	binary.BigEndian.PutUint32(buf[8:12], uint32(time.Now().Unix())) // UnixSecs
	binary.BigEndian.PutUint32(buf[12:16], 0)                  // UnixNano
	binary.BigEndian.PutUint32(buf[16:20], 1000)               // Seq
	buf[20] = 0                                                // EngineType
	buf[21] = 0                                                // EngineID
	binary.BigEndian.PutUint16(buf[22:24], 1000)               // SamplingRate 1:1000

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	popularDstASNs := []uint16{15169, 13335, 32934, 16509, 20940}

	for i := 0; i < recordCount; i++ {
		offset := 24 + (i * 48)
		rec := buf[offset : offset+48]

		// SrcIP: 103.145.2.x (ISP Customer range)
		rec[0] = 103
		rec[1] = 145
		rec[2] = 2
		rec[3] = byte(10 + r.Intn(240))

		// DstIP: Public internet
		rec[4] = byte(140 + r.Intn(60))
		rec[5] = byte(r.Intn(255))
		rec[6] = byte(r.Intn(255))
		rec[7] = byte(1 + r.Intn(254))

		// NextHop: 198.51.100.254
		rec[8] = 198
		rec[9] = 51
		rec[10] = 100
		rec[11] = 254

		// InputSNMP & OutputSNMP
		binary.BigEndian.PutUint16(rec[12:14], 1)
		binary.BigEndian.PutUint16(rec[14:16], 2)

		// Packets & Bytes
		pkts := uint32(10 + r.Intn(500))
		bytes := pkts * uint32(1200 + r.Intn(300))
		binary.BigEndian.PutUint32(rec[16:20], pkts)
		binary.BigEndian.PutUint32(rec[20:24], bytes)

		// Ports & Protocol
		srcPort := uint16(30000 + r.Intn(30000))
		dstPort := uint16(443)
		proto := uint8(6) // TCP
		if r.Intn(4) == 0 {
			dstPort = 53
			proto = 17 // UDP
		}
		binary.BigEndian.PutUint16(rec[32:34], srcPort)
		binary.BigEndian.PutUint16(rec[34:36], dstPort)
		rec[37] = 24 // TCP Flags PSH+ACK
		rec[38] = proto

		// ASNs (NetFlow v5 uses 16-bit ASNs)
		binary.BigEndian.PutUint16(rec[40:42], 64512)
		binary.BigEndian.PutUint16(rec[42:44], popularDstASNs[r.Intn(len(popularDstASNs))])
	}

	return buf
}

// DemoTrafficSimulator generates labeled demo traffic directly into ClickHouse sink.
type DemoTrafficSimulator struct {
	sink     *sink.ClickHouseSink
	siteID   string
	stopChan chan struct{}
}

func NewDemoTrafficSimulator(s *sink.ClickHouseSink, siteID string) *DemoTrafficSimulator {
	return &DemoTrafficSimulator{
		sink:     s,
		siteID:   siteID,
		stopChan: make(chan struct{}),
	}
}

func (d *DemoTrafficSimulator) Start(ratePPS int) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		popularDstASNs := []uint32{15169, 13335, 32934, 16509, 20940}

		for {
			select {
			case <-d.stopChan:
				return
			case <-ticker.C:
				records := make([]model.FlowRecord, 0, ratePPS)
				now := time.Now().UTC()

				for i := 0; i < ratePPS; i++ {
					pkts := uint64(5 + r.Intn(100))
					bytes := pkts * uint64(1200+r.Intn(300))
					proto := uint8(6)
					dstPort := uint16(443)
					if r.Intn(5) == 0 {
						proto = 17
						dstPort = 53
					}

					flow := model.FlowRecord{
						Timestamp:    now,
						SiteID:       d.siteID,
						ExporterIP:   "198.51.100.1",
						SrcIP:        fmt.Sprintf("103.145.2.%d", 10+r.Intn(240)),
						DstIP:        fmt.Sprintf("142.250.%d.%d", r.Intn(255), 1+r.Intn(254)),
						SrcPort:      uint16(32000 + r.Intn(30000)),
						DstPort:      dstPort,
						Protocol:     proto,
						TCPFlags:     24,
						Packets:      pkts * 1000,
						Bytes:        bytes * 1000,
						InputSNMP:    1,
						OutputSNMP:   2,
						NextHop:      "198.51.100.254",
						SrcAS:        136052,
						DstAS:        popularDstASNs[r.Intn(len(popularDstASNs))],
						SamplingRate: 1000,
						FlowFormat:   "simulator_v5",
						IsDemo:       1, // Explicitly labeled as demo data
					}
					records = append(records, flow)
				}

				d.sink.Ingest(records)
			}
		}
	}()
}

func (d *DemoTrafficSimulator) Stop() {
	close(d.stopChan)
}

// SendUDPPackets sends real binary NetFlow v5 packets to target UDP port.
func SendUDPPackets(targetAddr string, packetCount int) error {
	conn, err := net.Dial("udp", targetAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for i := 0; i < packetCount; i++ {
		pkt := GenerateNetFlow5Packet(10)
		_, err := conn.Write(pkt)
		if err != nil {
			return err
		}
	}
	return nil
}
