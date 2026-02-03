package codec

import (
    "encoding/binary"
    "errors"
    "github.com/SrabanMondal/proxy-vpn/internal/protocol/header"
)


type BinaryCodec struct{}

func NewBinaryCodec() *BinaryCodec {
	return &BinaryCodec{}
}

// Encode now takes the destination buffer as an argument.
func (c *BinaryCodec) Encode(h *header.Header, buf []byte) ([]byte, error) {
    if len(buf) < header.HeaderSize {
        return nil, errors.New("buffer too small for header")
    }

    binary.BigEndian.PutUint32(buf[0:4], h.SessionID)
    buf[4] = h.Type
    binary.BigEndian.PutUint32(buf[5:9], h.SeqID)
    binary.BigEndian.PutUint16(buf[9:11], h.Length)

    return buf[:header.HeaderSize+int(h.Length)], nil
}

// Decode the serialized into header and payload
func (c *BinaryCodec) Decode(b []byte) (*header.Header, []byte, error) {
    if len(b) < header.HeaderSize {
        return nil, nil, errors.New("packet too short")
    }

    h := &header.Header{
        SessionID: binary.BigEndian.Uint32(b[0:4]),
        Type:      b[4],
        SeqID:     binary.BigEndian.Uint32(b[5:9]),
        Length:    binary.BigEndian.Uint16(b[9:11]),
    }

    payload := b[header.HeaderSize : header.HeaderSize+int(h.Length)]

    return h, payload, nil
}