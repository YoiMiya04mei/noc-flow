package netflow9

import (
	"encoding/binary"
	"testing"
)

func buildSampleNetFlow9Packet() []byte {
	// Build a valid NetFlow v9 packet with:
	// - 20-byte Header
	// - Template FlowSet (FlowSet ID 0)
	// - Data FlowSet (FlowSet ID 256)

	// Template fields:
	// 1. IPV4_SRC_ADDR (type 8, len 4)
	// 2. IPV4_DST_ADDR (type 12, len 4)
	// 3. L4_SRC_PORT (type 7, len 2)
	// 4. L4_DST_PORT (type 11, len 2)
	// 5. PROTOCOL (type 4, len 1)
	// 6. IN_BYTES (type 1, len 4)
	// 7. IN_PKTS (type 2, len 4)
	// Record length = 4 + 4 + 2 + 2 + 1 + 4 + 4 = 21 bytes

	tmplFlowsetLen := 4 + 4 + (7 * 4) // 36 bytes
	dataFlowsetLen := 4 + 21          // 25 bytes
	totalLen := HeaderSize + tmplFlowsetLen + dataFlowsetLen

	buf := make([]byte, totalLen)

	// Packet Header (20 bytes)
	binary.BigEndian.PutUint16(buf[0:2], 9)                 // Version
	binary.BigEndian.PutUint16(buf[2:4], 2)                 // Count = 2 flowsets
	binary.BigEndian.PutUint32(buf[4:8], 50000)             // SysUptime
	binary.BigEndian.PutUint32(buf[8:12], 1700000000)       // UnixSecs
	binary.BigEndian.PutUint32(buf[12:16], 1)               // Seq
	binary.BigEndian.PutUint32(buf[16:20], 100)             // SourceID

	// Template FlowSet (starts at offset 20)
	tOff := 20
	binary.BigEndian.PutUint16(buf[tOff:tOff+2], 0)                          // FlowSet ID = 0 (Template)
	binary.BigEndian.PutUint16(buf[tOff+2:tOff+4], uint16(tmplFlowsetLen))   // Length
	binary.BigEndian.PutUint16(buf[tOff+4:tOff+6], 256)                      // Template ID = 256
	binary.BigEndian.PutUint16(buf[tOff+6:tOff+8], 7)                        // Field count = 7

	fields := []FieldSpec{
		{Type: FieldIPv4SrcAddr, Length: 4},
		{Type: FieldIPv4DstAddr, Length: 4},
		{Type: FieldL4SrcPort, Length: 2},
		{Type: FieldL4DstPort, Length: 2},
		{Type: FieldProtocol, Length: 1},
		{Type: FieldInBytes, Length: 4},
		{Type: FieldInPkts, Length: 4},
	}
	fOff := tOff + 8
	for _, f := range fields {
		binary.BigEndian.PutUint16(buf[fOff:fOff+2], f.Type)
		binary.BigEndian.PutUint16(buf[fOff+2:fOff+4], f.Length)
		fOff += 4
	}

	// Data FlowSet (starts at offset 20 + tmplFlowsetLen)
	dOff := 20 + tmplFlowsetLen
	binary.BigEndian.PutUint16(buf[dOff:dOff+2], 256)                       // FlowSet ID = 256
	binary.BigEndian.PutUint16(buf[dOff+2:dOff+4], uint16(dataFlowsetLen))  // Length

	rec := buf[dOff+4 : dOff+4+21]
	rec[0], rec[1], rec[2], rec[3] = 192, 168, 10, 50 // SrcIP 192.168.10.50
	rec[4], rec[5], rec[6], rec[7] = 1, 1, 1, 1       // DstIP 1.1.1.1
	binary.BigEndian.PutUint16(rec[8:10], 52000)      // SrcPort
	binary.BigEndian.PutUint16(rec[10:12], 443)       // DstPort
	rec[12] = 6                                       // Protocol TCP
	binary.BigEndian.PutUint32(rec[13:17], 150000)    // Bytes
	binary.BigEndian.PutUint32(rec[17:21], 100)       // Packets

	return buf
}

func TestParseNetFlow9Valid(t *testing.T) {
	packet := buildSampleNetFlow9Packet()
	store := NewTemplateStore()

	records, err := ParseWithStore(packet, "192.168.1.1", "POP-CGK-1", store)
	if err != nil {
		t.Fatalf("ParseWithStore failed: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("Expected 1 decoded record, got %d", len(records))
	}

	r := records[0]
	if r.SrcIP != "192.168.10.50" {
		t.Errorf("Expected SrcIP 192.168.10.50, got %s", r.SrcIP)
	}
	if r.DstIP != "1.1.1.1" {
		t.Errorf("Expected DstIP 1.1.1.1, got %s", r.DstIP)
	}
	if r.DstPort != 443 {
		t.Errorf("Expected DstPort 443, got %d", r.DstPort)
	}
	if r.Protocol != 6 {
		t.Errorf("Expected protocol 6, got %d", r.Protocol)
	}
	if r.Bytes != 150000 {
		t.Errorf("Expected bytes 150000, got %d", r.Bytes)
	}
	if r.Packets != 100 {
		t.Errorf("Expected packets 100, got %d", r.Packets)
	}
}

func TestParseNetFlow9CorruptedDoesNotPanic(t *testing.T) {
	corrupted := []byte{0x00, 0x09, 0x00, 0x05, 0xFF, 0xFF}
	_, err := Parse(corrupted, "127.0.0.1", "TEST")
	if err == nil {
		t.Errorf("Expected error on truncated NetFlow v9 packet, got nil")
	}
}
