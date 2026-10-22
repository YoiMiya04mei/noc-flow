package ipfix

import (
	"encoding/binary"
	"testing"
)

func TestIPFIXShortPacketError(t *testing.T) {
	shortData := []byte{0x00, 0x0A, 0x00}
	_, err := Parse(shortData, "127.0.0.1", "SITE-A")
	if err == nil {
		t.Fatalf("Expected error on truncated IPFIX packet, got nil")
	}
}

func TestIPFIXInvalidVersion(t *testing.T) {
	invalidVer := make([]byte, 20)
	binary.BigEndian.PutUint16(invalidVer[0:2], 99) // Invalid version
	binary.BigEndian.PutUint16(invalidVer[2:4], 20) // Length
	_, err := Parse(invalidVer, "127.0.0.1", "SITE-A")
	if err == nil {
		t.Fatalf("Expected error on invalid IPFIX version, got nil")
	}
}
