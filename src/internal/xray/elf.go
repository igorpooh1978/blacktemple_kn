package xray

import (
	"archive/zip"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"strings"
)

// CheckMIPSLESoftfloatELF verifies a KN-1011 candidate binary: ELF32 little-endian MIPS.
// It does not execute the file.
func CheckMIPSLESoftfloatELF(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("not ELF: %w", err)
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS32 {
		return fmt.Errorf("class %s want ELFCLASS32", f.Class)
	}
	if f.Data != elf.ELFDATA2LSB {
		return fmt.Errorf("endian %s want LSB", f.Data)
	}
	if f.Machine != elf.EM_MIPS {
		return fmt.Errorf("machine %s want EM_MIPS", f.Machine)
	}
	return nil
}

// ZipContainsSoftfloat reports whether an official Xray zip lists xray_softfloat.
func ZipContainsSoftfloat(zipPath string) (bool, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return false, err
	}
	defer r.Close()
	for _, f := range r.File {
		name := f.Name
		if i := strings.LastIndexAny(name, `/\`); i >= 0 {
			name = name[i+1:]
		}
		if name == "xray_softfloat" {
			return true, nil
		}
	}
	return false, nil
}

// ExtractZipFile writes one entry from zipPath into destPath.
func ExtractZipFile(zipPath, name, destPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		base := f.Name
		if i := strings.LastIndexAny(base, `/\`); i >= 0 {
			base = base[i+1:]
		}
		if base != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(destPath)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		closeErr := out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	return fmt.Errorf("%s not found in zip", name)
}
