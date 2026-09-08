package connection

import (
	"errors"
	"net/http"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

type codedError struct {
	status int
	msg    string
	cause  error
}

func (e *codedError) Error() string {
	if e.cause != nil {
		return e.cause.Error()
	}
	return e.msg
}

func (e *codedError) Unwrap() error { return e.cause }

func (e *codedError) HTTPStatus() int { return e.status }

func (e *codedError) PublicMessage() string { return e.msg }

func codeControl(err error) error {
	if err == nil {
		return nil
	}
	var existing *codedError
	if errors.As(err, &existing) {
		return err
	}
	switch {
	case errors.Is(err, ErrUnsupportedInEnvironment):
		return &codedError{status: http.StatusNotImplemented, msg: "not implemented", cause: err}
	case errors.Is(err, ErrNoProfile),
		errors.Is(err, ErrNoCandidate),
		errors.Is(err, ErrUnsupportedProtocol),
		errors.Is(err, ErrValidate),
		errors.Is(err, ErrNotConnected):
		return &codedError{status: http.StatusBadRequest, msg: publicError(err), cause: err}
	case errors.Is(err, ErrMissingXray),
		errors.Is(err, ErrStart):
		return &codedError{status: http.StatusInternalServerError, msg: publicError(err), cause: err}
	default:
		return &codedError{status: http.StatusInternalServerError, msg: "control failed", cause: err}
	}
}

func codeImport(err error) error {
	if err == nil {
		return nil
	}
	var existing *codedError
	if errors.As(err, &existing) {
		return err
	}
	switch {
	case errors.Is(err, profiles.ErrEmptyImport),
		errors.Is(err, subscription.ErrEmpty),
		errors.Is(err, subscription.ErrMalformed),
		errors.Is(err, subscription.ErrUnknownJSON),
		errors.Is(err, subscription.ErrUnsupportedURL):
		return &codedError{status: http.StatusBadRequest, msg: "invalid request", cause: err}
	default:
		return &codedError{status: http.StatusInternalServerError, msg: "import failed", cause: err}
	}
}
