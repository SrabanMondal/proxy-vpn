package protocol

import "encoding/binary"

// EncodeNACKPayload serializes missing sequence IDs as a compact uint32 list.
func EncodeNACKPayload(missing []uint32) []byte {
	if len(missing) == 0 {
		return nil
	}

	out := make([]byte, len(missing)*4)
	for i, seq := range missing {
		binary.BigEndian.PutUint32(out[i*4:(i+1)*4], seq)
	}
	return out
}

// DecodeNACKPayload parses missing sequence IDs encoded by EncodeNACKPayload.
func DecodeNACKPayload(payload []byte) []uint32 {
	if len(payload) < 4 {
		return nil
	}

	count := len(payload) / 4
	out := make([]uint32, 0, count)
	for i := 0; i < count; i++ {
		start := i * 4
		out = append(out, binary.BigEndian.Uint32(payload[start:start+4]))
	}
	return out
}
