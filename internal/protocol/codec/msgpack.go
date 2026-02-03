package codec

// import (
// 	"fmt"

// 	"github.com/vmihailenco/msgpack/v5"
// 	"github.com/SrabanMondal/proxy-vpn/internal/protocol/header"
// )

// // MsgPackCodec implements the Codec interface using msgpack-v5.
// type MsgPackCodec struct{}

// func NewMsgPackCodec() *MsgPackCodec {
// 	return &MsgPackCodec{}
// }

// // msgpackFrame is the structure encoded over the wire.
// type msgpackFrame struct {
// 	SessionID uint32 `msgpack:"sid"`
// 	Type      uint8  `msgpack:"type"`
// 	SeqID     uint32 `msgpack:"seq"`
// 	Payload   []byte `msgpack:"payload"`
// }

// func (c *MsgPackCodec) Encode(h *header.Header, payload []byte) ([]byte, error) {
// 	frame := msgpackFrame{
// 		SessionID: h.SessionID,
// 		Type:      h.Type,
// 		SeqID:     h.SeqID,
// 		Payload:   payload,
// 	}
// 	return msgpack.Marshal(&frame)
// }

// func (c *MsgPackCodec) Decode(b []byte) (*header.Header, []byte, error) {
// 	var frame msgpackFrame
// 	if err := msgpack.Unmarshal(b, &frame); err != nil {
// 		return nil, nil, fmt.Errorf("msgpack decode: %w", err)
// 	}

// 	h := &header.Header{
// 		SessionID: frame.SessionID,
// 		Type:      frame.Type,
// 		SeqID:     frame.SeqID,
// 		Length:    uint16(len(frame.Payload)),
// 	}

// 	return h, frame.Payload, nil
// }
