package protocol

import (
	"fmt"

	"github.com/SrabanMondal/proxy-vpn/internal/protocol/codec"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol/crypto"
)

// Parser performs the reverse of Builder:
//    encrypted bytes → decrypted bytes → decoded header+payload → Packet
type Parser struct{}

// NewParser constructs a new parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse takes encrypted UDP bytes and produces a fully structured Packet.
func (p *Parser) Parse(encrypted []byte, buffer []byte) (*Packet, error) {

	decodedBytes, err := crypto.C().Decrypt(encrypted)
	// fmt.Println("Decrypted packet: ",string(decodedBytes))
	if err != nil {
		return nil, fmt.Errorf("packet decrypt: %w", err)
	}

	h, payload, err := codec.C().Decode(decodedBytes)
	if err != nil {
		return nil, fmt.Errorf("packet decode: %w", err)
	}

	pkt := &Packet{
		Header:  h,
		Payload: payload,
		Buffer: buffer,
	}

	return pkt, nil
}