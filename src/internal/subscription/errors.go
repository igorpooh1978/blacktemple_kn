package subscription

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
)

const (
	ClassInvalidSubscription = "INVALID_SUBSCRIPTION"
	ClassTooLarge            = "FETCH_TOO_LARGE"
	ClassFetchFailed         = "FETCH_FAILED"
	ClassFetchTimeout        = "FETCH_TIMEOUT"
	ClassHTTPError           = "HTTP_ERROR"
	ClassTLSError            = "TLS_ERROR"
)

const (
	publicInvalidFormat = "Ключ или подписка имеют неизвестный формат."
	publicTooLarge      = "Подписка слишком большая."
	publicFetchFailed   = "Не удалось загрузить подписку."
	publicFetchTimeout  = "Сервер подписки не ответил вовремя."
)

var (
	ErrFetchFailed  = errors.New("subscription fetch failed")
	ErrFetchTimeout = errors.New("subscription fetch timeout")
	ErrHTTPStatus   = errors.New("subscription HTTP error")
	ErrTLS          = errors.New("subscription TLS error")
)

// ClassifiedError is a public-safe fetch/parse failure. Error() never includes
// URLs, query tokens, Authorization, or upstream bodies.
type ClassifiedError struct {
	Class  string
	Status int
	Public string
	cause  error
}

func (e *ClassifiedError) Error() string {
	if e == nil {
		return "subscription error"
	}
	if e.Class != "" {
		return "subscription " + e.Class
	}
	return "subscription error"
}

func (e *ClassifiedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *ClassifiedError) HTTPStatus() int {
	if e == nil {
		return 0
	}
	return e.Status
}

func (e *ClassifiedError) PublicMessage() string {
	if e == nil {
		return ""
	}
	return e.Public
}

func ClassifyParse(err error) error {
	if err == nil {
		return nil
	}
	var ce *ClassifiedError
	if errors.As(err, &ce) {
		return err
	}
	if errors.Is(err, ErrEmpty) || errors.Is(err, ErrMalformed) || errors.Is(err, ErrUnknownJSON) || errors.Is(err, ErrUnsupportedURL) {
		return &ClassifiedError{
			Class:  ClassInvalidSubscription,
			Status: 400,
			Public: publicInvalidFormat,
			cause:  err,
		}
	}
	if errors.Is(err, ErrBodyTooLarge) {
		return &ClassifiedError{
			Class:  ClassTooLarge,
			Status: 413,
			Public: publicTooLarge,
			cause:  err,
		}
	}
	return err
}

func classifyDoError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return &ClassifiedError{Class: ClassFetchTimeout, Status: 504, Public: publicFetchTimeout, cause: ErrFetchTimeout}
	}
	if isTimeout(err) {
		return &ClassifiedError{Class: ClassFetchTimeout, Status: 504, Public: publicFetchTimeout, cause: ErrFetchTimeout}
	}
	if isTLSError(err) {
		return &ClassifiedError{Class: ClassTLSError, Status: 502, Public: publicFetchFailed, cause: ErrTLS}
	}
	return &ClassifiedError{Class: ClassFetchFailed, Status: 502, Public: publicFetchFailed, cause: ErrFetchFailed}
}

func classifyHTTPStatus(code int) error {
	_ = code
	return &ClassifiedError{Class: ClassHTTPError, Status: 502, Public: publicFetchFailed, cause: ErrHTTPStatus}
}

func classifyReadError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return &ClassifiedError{Class: ClassFetchFailed, Status: 502, Public: publicFetchFailed, cause: ErrFetchFailed}
	}
	return classifyDoError(err)
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}

func isTLSError(err error) bool {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var sr x509.SystemRootsError
	var cv *tls.CertificateVerificationError
	if errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) || errors.As(err, &sr) || errors.As(err, &cv) {
		return true
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return isTLSError(ue.Err)
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "x509:") || strings.Contains(msg, "tls:") || strings.Contains(msg, "certificate")
}
