package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	dataDir := flag.String("data", "", "directory packed as data.tar.gz (Unix paths as-is from dir root)")
	controlDir := flag.String("control", "", "directory packed as control.tar.gz")
	out := flag.String("out", "", "output .ipk path")
	epoch := flag.Int64("epoch", 0, "SOURCE_DATE_EPOCH")
	expectArch := flag.String("expect-arch", "", "if set, require Architecture in control to match")
	chmod := flag.String("chmod", "", "comma-separated tar-path=octal mode overrides (Unix bits)")
	flag.Parse()
	if *dataDir == "" || *controlDir == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: ipkpack -data <dir> -control <dir> -out <file.ipk> [-epoch N] [-expect-arch ARCH] [-chmod path=0755,...]")
		os.Exit(2)
	}
	if *expectArch != "" {
		got, err := readControlArchitecture(*controlDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		if got != *expectArch {
			fmt.Fprintf(os.Stderr, "FAIL: Architecture %q want %q\n", got, *expectArch)
			os.Exit(1)
		}
	}
	modeMap, err := parseChmod(*chmod)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(2)
	}
	if err := packWith(*dataDir, *controlDir, *out, *epoch, modeMap); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS %s\n", *out)
}

func pack(dataDir, controlDir, out string, epoch int64) error {
	return packWith(dataDir, controlDir, out, epoch, nil)
}

func packWith(dataDir, controlDir, out string, epoch int64, chmod map[string]int64) error {
	mt := time.Unix(epoch, 0).UTC()
	controlGZ, err := tarGzDir(controlDir, mt, chmod)
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	dataGZ, err := tarGzDir(dataDir, mt, chmod)
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	debian := []byte("2.0\n")
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, m := range []struct {
		name string
		data []byte
	}{
		{name: "./debian-binary", data: debian},
		{name: "./data.tar.gz", data: dataGZ},
		{name: "./control.tar.gz", data: controlGZ},
	} {
		hdr := &tar.Header{
			Name:    m.name,
			Mode:    0o644,
			Size:    int64(len(m.data)),
			ModTime: mt,
			Uid:     0,
			Gid:     0,
			Uname:   "root",
			Gname:   "root",
			Format:  tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(m.data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	zw.Name = ""
	zw.ModTime = mt
	zw.OS = 3
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil && !os.IsExist(err) {
		if filepath.Dir(out) != "." {
			return err
		}
	}
	return os.WriteFile(out, gzBuf.Bytes(), 0o644)
}

func tarGzDir(root string, mt time.Time, chmod map[string]int64) ([]byte, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, rel := range files {
		abs := filepath.Join(root, rel)
		info, err := os.Lstat(abs)
		if err != nil {
			return nil, err
		}
		name := "./" + path.Clean(filepath.ToSlash(rel))
		if name == "./." {
			continue
		}
		var payload []byte
		if info.Mode().IsRegular() {
			payload, err = os.ReadFile(abs)
			if err != nil {
				return nil, err
			}
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return nil, err
		}
		hdr.Name = name
		hdr.Uid = 0
		hdr.Gid = 0
		hdr.Uname = "root"
		hdr.Gname = "root"
		hdr.ModTime = mt
		hdr.AccessTime = time.Time{}
		hdr.ChangeTime = time.Time{}
		hdr.Format = tar.FormatUSTAR
		hdr.Mode = unixMode(info, payload)
		if chmod != nil {
			key := strings.TrimPrefix(name, "./")
			if mode, ok := chmod[key]; ok {
				hdr.Mode = mode
			} else if mode, ok := chmod[name]; ok {
				hdr.Mode = mode
			}
		}
		if info.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
			hdr.Name += "/"
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(abs)
			if err != nil {
				return nil, err
			}
			hdr.Linkname = filepath.ToSlash(target)
			hdr.Typeflag = tar.TypeSymlink
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if info.Mode().IsRegular() {
			if _, err := tw.Write(payload); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	zw.Name = ""
	zw.ModTime = mt
	zw.OS = 3 // Unix
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return gzBuf.Bytes(), nil
}

func validateIpk(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		return fmt.Errorf("missing gzip magic")
	}
	return nil
}

func unixMode(info fs.FileInfo, payload []byte) int64 {
	if info.IsDir() {
		return 0o755
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return 0o777
	}
	if isExecutablePayload(payload) {
		return 0o755
	}
	return 0o644
}

func isExecutablePayload(b []byte) bool {
	if len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return true
	}
	if len(b) >= 2 && b[0] == '#' && b[1] == '!' {
		return true
	}
	return false
}

func parseChmod(s string) (map[string]int64, error) {
	out := map[string]int64{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("chmod entry %q: want path=octal", part)
		}
		mode, err := strconv.ParseInt(strings.TrimSpace(v), 8, 64)
		if err != nil {
			return nil, fmt.Errorf("chmod %q: %w", part, err)
		}
		out[path.Clean(filepath.ToSlash(strings.TrimSpace(k)))] = mode
	}
	return out, nil
}

func readControlArchitecture(controlDir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(controlDir, "control"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "Architecture:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Architecture:")), nil
		}
	}
	return "", fmt.Errorf("Architecture field missing in control")
}
