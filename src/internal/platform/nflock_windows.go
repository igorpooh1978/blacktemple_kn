//go:build windows

package platform

import (
	"context"
	"os"
)

func getenv(key string) string { return os.Getenv(key) }

func acquireNFLock(context.Context, string) (func(), error) {
	return func() {}, nil
}
