package sflow5

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestSFlow5ShortPacketError(t *testing.T) {
	shortData := []byte{0x00, 0x00, 0x00, 0x05, 0x00}
	_, err := Parse(shortData, "127.0.0.1", "SITE-A")
	if err == nil {
		t.Fatalf("Expected error on truncated sFlow packet, got nil")
	}
}

func TestSFlow5InvalidVersion(t *testing.T) {
	invalidVer := make([]byte, 32)
	binary.BigEndian.PutUint32(invalidVer[0:4], 4) // Version 4 instead of 5
	_, err := Parse(invalidVer, "127.0.0.1", "SITE-A")
	if err == nil {
		t.Fatalf("Expected error on non-v5 sFlow packet, got nil")
	}
}

func TestDecodeEthernetPacket(t *testing.T) {
	// Build minimal Ethernet + IPv4 + UDP packet
	rawPkt := make([]byte, 14+20+8)

	// Ethernet Header (14 bytes)
	rawPkt[12] = 0x08
	rawPkt[13] = 0x00 // EtherType IPv4

	// IPv4 Header (20 bytes)
	ipHdr := rawPkt[14 : 14+20]
	ipHdr[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(ipHdr[2:4], 28) // Total length
	ipHdr[9] = 17 // UDP
	ipHdr[12], ipHdr[13], ipHdr[14], ipHdr[15] = 10, 0, 0, 1 // SrcIP
	ipHdr[16], ipHdr[17], ipHdr[18], ipHdr[19] = 10, 0, 0, 2 // DstIP

	// UDP Header (8 bytes)
	udpHdr := rawPkt[34:]
	binary.BigEndian.PutUint16(udpHdr[0:2], 12345) // SrcPort
	binary.BigEndian.PutUint16(udpHdr[2:4], 53)    // DstPort

	flow := decodeEthernetPacket(rawPkt, time.Now().UTC(), "10.0.0.254", "SITE-1", 1000, 1, 2, 42)
	if flow == nil {
		t.Fatalf("Expected valid flow record, got nil")
	}

	if flow.SrcIP != "10.0.0.1" {
		t.Errorf("Expected SrcIP 10.0.0.1, got %s", flow.SrcIP)
	}
	if flow.DstIP != "10.0.0.2" {
		t.Errorf("Expected DstIP 10.0.0.2, got %s", flow.DstIP)
	}
	if flow.SrcPort != 12345 {
		t.Errorf("Expected SrcPort 12345, got %d", flow.SrcPort)
	}
	if flow.DstPort != 53 {
		t.Errorf("Expected DstPort 53, got %d", flow.DstPort)
	}
	if flow.Protocol != 17 {
		t.Errorf("Expected protocol 17 (UDP), got %d", flow.Protocol)
	}
	if flow.FlowFormat != "sflow5" {
		t.Errorf("Expected format sflow5, got %s", flow.FlowFormat)
	}
}
