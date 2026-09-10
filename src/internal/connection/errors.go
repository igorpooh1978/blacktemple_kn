package connection

import "errors"

var (
	ErrNoProfile                  = errors.New("no profile")
	ErrNoCandidate                = errors.New("no connection candidate")
	ErrBlackKeyResolutionRequired = errors.New("blackkey resolution required")
	ErrUnsupportedProtocol        = errors.New("unsupported protocol")
	ErrMissingXray                = errors.New("xray executable is missing")
	ErrValidate                   = errors.New("xray config validation failed")
	ErrStart                      = errors.New("xray start failed")
	ErrUnsupportedInEnvironment   = errors.New("explicitly unsupported in current environment")
	ErrNotConnected               = errors.New("not connected")
)

const ClassBlackKeyResolutionRequired = "BLACKKEY_RESOLUTION_REQUIRED"
