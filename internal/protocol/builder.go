package protocol

import (
	"fmt"
	//"log"

	"github.com/SrabanMondal/proxy-vpn/internal/protocol/codec"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol/crypto"
)

// Builder handles conversion of Packet → encoded+encrypted bytes.
type Builder struct{}

// NewBuilder returns a new Builder instance.
func NewBuilder() *Builder {
	return &Builder{}
}

// Build takes a Packet and produces the final encrypted wire format:
//
//    Packet
//      ↓
//    codec.Encode()     → serializedFrame []byte
//      ↓
//    crypto.Encrypt()   → finalWireBytes []byte
func (b *Builder) Build(p *Packet) (OutboundWork, error) {

	//log.Printf("[BUILDER] Packet Payload (len-%d) Buffer (len-%d)",len(p.Payload), len(p.Buffer))
	encoded, err := codec.C().Encode(p.Header, p.Buffer)
	//log.Printf("encoded packet length must be 1460 bytes (len-%d)", len(encoded))
	if err != nil {
		return OutboundWork{}, fmt.Errorf("packet encode: %w", err)
	}

	encrypted, err := crypto.C().Encrypt(p.Buffer, encoded)
	if err != nil {
		return OutboundWork{}, fmt.Errorf("packet encrypt: %w", err)
	}

	return OutboundWork{
		Data: encrypted, OriginalBuffer: p.Buffer,
	}, nil
}
