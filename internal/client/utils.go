package client

import (
	"encoding/binary"
	"strconv"
	"sync/atomic"
)

var globalSessionID uint32

// GenerateSessionID returns a unique uint32 session ID
func GenerateSessionID() uint32 {
	return atomic.AddUint32(&globalSessionID, 1)
}

// ParsePort converts a string port to uint16
func ParsePort(portStr string) (uint16, error) {
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	return uint16(p), nil
}

// Uint16ToBytes converts uint16 to big-endian bytes
func Uint16ToBytes(p uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, p)
	return buf
}

// BytesToUint16 converts 2-byte big-endian slice to uint16
func BytesToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}
