package remotelists

import "errors"

var (
	ErrInvalidID                    = errors.New("invalid list id")
	ErrUnknownType                  = errors.New("unknown list type")
	ErrHTTPSRequired                = errors.New("remote list URL must be https")
	ErrBlockedScheme                = errors.New("remote list URL scheme is not allowed")
	ErrBlockedDestination           = errors.New("remote list destination is blocked")
	ErrTooLarge                     = errors.New("remote list exceeds size limit")
	ErrTooManyLines                 = errors.New("remote list exceeds line count limit")
	ErrInvalidContent               = errors.New("remote list content is invalid")
	ErrChecksumMismatch             = errors.New("remote list checksum mismatch")
	ErrNotModified                  = errors.New("remote list not modified")
	ErrNoCache                      = errors.New("no last-known-good cache")
	ErrRedirect                     = errors.New("remote list redirect is blocked")
	ErrTooManyRedirects             = errors.New("too many redirects")
	ErrTimeout                      = errors.New("remote list fetch timed out")
	ErrProviderFormatNotImplemented = errors.New("PROVIDER FORMAT: NOT IMPLEMENTED")
	ErrUntrustedOrigin              = errors.New("remote list origin is not trusted")
)
