package stcp

import "errors"

var (
	ErrServerClosed       = errors.New("server closed")
	ErrKeyNotExist        = errors.New("key not exist")
	ErrHandlerNotFound    = errors.New("handler not found")
	ErrAESGCMNotInit      = errors.New("aesgcm not init")
	ErrCipherTooShort     = errors.New("cipher too short")
	ErrFailResponse       = errors.New("fail response")
	ErrEmptyBody          = errors.New("empty body")
	ErrInvalidMessageType = errors.New("invalid message type")
	ErrInvalidVersion     = errors.New("invalid version")
	ErrBodyToolong        = errors.New("body too long")
	ErrUnexpectedPrefix   = errors.New("unexpected prefix")
	ErrPacketTooLarge     = errors.New("packet too large")
)
