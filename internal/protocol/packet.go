package protocol

import (
	"github.com/SrabanMondal/proxy-vpn/internal/protocol/header"
)

// Packet is the in-memory representation of a Proxy packet.
//   - Header is a fixed binary structure (sessionID, seqID, type, length)
//   - Payload is raw unprocessed data
//   - Buffer is the memory allocated to packet
type Packet struct {
	Header  *header.Header
	Payload []byte
	Buffer  []byte
}

// NewPacket constructs a Packet
func NewPacket(sessionID uint32, pType uint8, seqID uint32, payload []byte, buffer []byte) *Packet {
	return &Packet{
		Header: &header.Header{
			SessionID: sessionID,
			Type:      pType,
			SeqID:     seqID,
			Length:    uint16(len(payload)),
		},
		Payload: payload,
		Buffer: buffer,
	}
}

type OutboundWork struct {
    Data           []byte
    OriginalBuffer []byte
}
