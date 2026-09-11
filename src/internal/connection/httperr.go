package connection

import (
	"errors"
	"net/http"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/xray"
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
		errors.Is(err, ErrNotConnected),
		errors.Is(err, xray.ErrInvalidVLESSUserID),
		errors.Is(err, xray.ErrInvalidRealityPublicKey),
		errors.Is(err, xray.ErrInvalidRealityShortID):
		return &codedError{status: http.StatusBadRequest, msg: publicError(err), cause: err}
	case errors.Is(err, ErrBlackKeyResolutionRequired):
		return &codedError{status: http.StatusConflict, msg: publicError(err), cause: err}
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
	type publicer interface {
		HTTPStatus() int
		PublicMessage() string
	}
	var pe publicer
	if errors.As(err, &pe) && pe.HTTPStatus() > 0 {
		return err
	}
	switch {
	case errors.Is(err, profiles.ErrEmptyImport),
		errors.Is(err, subscription.ErrEmpty),
		errors.Is(err, subscription.ErrMalformed),
		errors.Is(err, subscription.ErrUnknownJSON),
		errors.Is(err, subscription.ErrUnsupportedURL),
		errors.Is(err, profiles.ErrUnsupportedProtocol):
		return &codedError{status: http.StatusBadRequest, msg: "Ключ или подписка имеют неизвестный формат.", cause: err}
	case errors.Is(err, subscription.ErrBodyTooLarge):
		return &codedError{status: http.StatusRequestEntityTooLarge, msg: "Подписка слишком большая.", cause: err}
	case errors.Is(err, profiles.ErrResolverNotConfigured):
		return &codedError{status: http.StatusServiceUnavailable, msg: "Резолвер ключа не настроен.", cause: err}
	case errors.Is(err, profiles.ErrResolverUnavailable),
		errors.Is(err, profiles.ErrResolverInvalidResponse),
		errors.Is(err, profiles.ErrResolverRejected):
		return &codedError{status: http.StatusBadGateway, msg: "Не удалось обновить список серверов. Сохранённый рабочий сервер оставлен без изменений.", cause: err}
	default:
		return &codedError{status: http.StatusInternalServerError, msg: "import failed", cause: err}
	}
}
