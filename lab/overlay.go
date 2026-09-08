package lab

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PrepareOverlay gunzips the pinned rootfs and creates a qcow2 overlay.
// The golden image is never modified. Missing qemu-img is reported, not silent.
func PrepareOverlay(qemuImg, gzPath, workDir string) (string, error) {
	if qemuImg == "" {
		return "", fmt.Errorf("qemu-img not found; overlay not created")
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return "", err
	}
	raw := filepath.Join(workDir, "rootfs-ext4.img")
	overlay := filepath.Join(workDir, "overlay.qcow2")
	if err := gunzipTo(gzPath, raw); err != nil {
		return "", err
	}
	_ = os.Remove(overlay)
	cmd := exec.Command(qemuImg, "create", "-f", "qcow2", "-F", "raw", "-b", raw, overlay)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("qemu-img overlay: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return overlay, nil
}

func gunzipTo(gzPath, dest string) error {
	in, err := os.Open(gzPath)
	if err != nil {
		return err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("gzip %s: %w", gzPath, err)
	}
	defer zr.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, zr); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
