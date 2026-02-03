package header

// HeaderSize defines the exact encoded size of the packet header.
// SessionID (4) + Type (1) + SeqID (4) + Length (2)
const HeaderSize = 4 + 1 + 4 + 2

// PacketType identifies the type of message.
const (
	TYPE_CONNECT uint8 = 1
	TYPE_DATA    uint8 = 2
	TYPE_FIN     uint8 = 3
	TYPE_PING    uint8 = 4
	TYPE_PONG    uint8 = 5
)

// Header represents the fixed header in every packet.
type Header struct {
	SessionID uint32
	Type      uint8
	SeqID     uint32
	Length    uint16 // length of the payload
}