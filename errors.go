package stcp

import "errors"

var (
	ErrServerClosed     = errors.New("server closed")
	ErrAESGCMNotInit    = errors.New("aesgcm not init")
	ErrCipherTooShort   = errors.New("cipher too short")
	ErrFailResponse     = errors.New("fail response")
	ErrEmptyBody        = errors.New("empty body")
	ErrInvalidVersion   = errors.New("invalid version")
	ErrBodyToolong      = errors.New("body too long")
	ErrUnexpectedPrefix = errors.New("unexpected prefix")
	ErrPacketTooLarge   = errors.New("packet too large")
	ErrSessionNotFound  = errors.New("session not found")
	ErrSessionExpired   = errors.New("session expired")
	ErrInvalidBody      = errors.New("invalid body")
)
