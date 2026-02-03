package codec

import (
	"errors"

	"github.com/SrabanMondal/proxy-vpn/internal/protocol/header"
)

// Codec defines how packet header + payload are serialized into bytes,
type Codec interface {

	Encode(h *header.Header, payload []byte) ([]byte, error)

	Decode(b []byte) (*header.Header, []byte, error)
}

const (
	CodecBinary  = "binary"
	CodecMsgPack = "msgpack"
	CodecProto   = "protobuf"
)

var (
	ErrUnknownCodec = errors.New("unknown codec type")
)

// codecInstance stores the selected codec implementation.
var codecInstance Codec

// SetCodec selects and initializes the global codec implementation.
func SetCodec(name string) error {
	switch name {
	case CodecBinary:
        codecInstance = NewBinaryCodec()
	// case CodecMsgPack:
	// 	codecInstance = NewMsgPackCodec()
	// case CodecProto:
	// 	codecInstance = NewProtoCodec()
	default:
		return ErrUnknownCodec
	}
	return nil
}

// C returns the global codec instance.
func C() Codec {
	if codecInstance == nil {
		panic("codec not initialized — call SetCodec(name) at startup")
	}
	return codecInstance
}
