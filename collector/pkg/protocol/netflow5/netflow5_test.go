package netflow5

import (
	"encoding/binary"
	"testing"
)

func buildSampleNetFlow5Packet(records int) []byte {
	totalLen := HeaderSize + (records * RecordSize)
	buf := make([]byte, totalLen)

	// Header
	binary.BigEndian.PutUint16(buf[0:2], 5)                  // Version
	binary.BigEndian.PutUint16(buf[2:4], uint16(records))   // Count
	binary.BigEndian.PutUint32(buf[4:8], 10000)             // SysUptime
	binary.BigEndian.PutUint32(buf[8:12], 1700000000)       // UnixSecs
	binary.BigEndian.PutUint16(buf[22:24], 100)             // SamplingRate 100

	for i := 0; i < records; i++ {
		offset := HeaderSize + (i * RecordSize)
		rec := buf[offset : offset+RecordSize]

		rec[0], rec[1], rec[2], rec[3] = 10, 0, 1, byte(i+1) // SrcIP 10.0.1.x
		rec[4], rec[5], rec[6], rec[7] = 8, 8, 8, 8         // DstIP 8.8.8.8
		rec[8], rec[9], rec[10], rec[11] = 192, 168, 1, 1  // NextHop

		binary.BigEndian.PutUint16(rec[12:14], uint16(i+1)) // In SNMP
		binary.BigEndian.PutUint16(rec[14:16], 2)           // Out SNMP
		binary.BigEndian.PutUint32(rec[16:20], 50)          // Packets
		binary.BigEndian.PutUint32(rec[20:24], 71000)       // Octets

		binary.BigEndian.PutUint16(rec[32:34], 45000)       // SrcPort
		binary.BigEndian.PutUint16(rec[34:36], 443)         // DstPort
		rec[37] = 24                                        // TCPFlags
		rec[38] = 6                                         // Protocol TCP
		binary.BigEndian.PutUint16(rec[40:42], 64512)       // SrcAS (16-bit)
		binary.BigEndian.PutUint16(rec[42:44], 15169)       // DstAS
	}

	return buf
}

func TestParseValidNetFlow5(t *testing.T) {
	packet := buildSampleNetFlow5Packet(5)
	records, err := Parse(packet, "192.168.1.1", "POP-CGK-1")
	if err != nil {
		t.Fatalf("Parse failed unexpectedly: %v", err)
	}

	if len(records) != 5 {
		t.Fatalf("Expected 5 records, got %d", len(records))
	}

	r0 := records[0]
	if r0.SrcIP != "10.0.1.1" {
		t.Errorf("Expected SrcIP 10.0.1.1, got %s", r0.SrcIP)
	}
	if r0.DstIP != "8.8.8.8" {
		t.Errorf("Expected DstIP 8.8.8.8, got %s", r0.DstIP)
	}
	if r0.Protocol != 6 {
		t.Errorf("Expected protocol 6, got %d", r0.Protocol)
	}
	if r0.DstPort != 443 {
		t.Errorf("Expected DstPort 443, got %d", r0.DstPort)
	}
	if r0.SamplingRate != 100 {
		t.Errorf("Expected sampling rate 100, got %d", r0.SamplingRate)
	}
	// Packets = 50 * samplingRate (100) = 5000
	if r0.Packets != 5000 {
		t.Errorf("Expected packets adjusted for sampling 5000, got %d", r0.Packets)
	}
}

func TestParseTruncatedPacketDoesNotPanic(t *testing.T) {
	shortData := []byte{0x00, 0x05, 0x00, 0x01}
	_, err := Parse(shortData, "127.0.0.1", "TEST")
	if err == nil {
		t.Errorf("Expected error on truncated packet, got nil")
	}
}

func TestParseInvalidVersion(t *testing.T) {
	buf := buildSampleNetFlow5Packet(1)
	binary.BigEndian.PutUint16(buf[0:2], 7) // Version 7 (invalid)
	_, err := Parse(buf, "127.0.0.1", "TEST")
	if err == nil {
		t.Errorf("Expected error for invalid version, got nil")
	}
}
