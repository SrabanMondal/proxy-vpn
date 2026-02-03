package protocol

import "errors"

var (
	ErrDecryptFailed = errors.New("protocol: decrypt failed")

	ErrDecodeFailed = errors.New("protocol: decode failed")

	ErrInvalidHeader = errors.New("protocol: invalid header")

	ErrUnknownSession = errors.New("protocol: unknown session")

	ErrUnknownPacketType = errors.New("protocol: unknown packet type")

	ErrPayloadLengthMismatch = errors.New("protocol: payload length mismatch")
)
