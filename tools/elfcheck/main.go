package main

import (
	"debug/elf"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

const (
	emMIPS = 8
	mz     = 0x5A4D
)

func main() {
	expectClass := flag.String("class", "32", "ELF class: 32 or 64")
	expectEndian := flag.String("endian", "le", "endian: le or be")
	expectMachine := flag.String("machine", "mips", "machine: mips")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: elfcheck [flags] <file>")
		os.Exit(2)
	}
	path := flag.Arg(0)
	if err := check(path, *expectClass, *expectEndian, *expectMachine); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("PASS %s\n", path)
}

func check(path, expectClass, expectEndian, expectMachine string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(raw) >= 2 && binary.LittleEndian.Uint16(raw[:2]) == mz {
		return fmt.Errorf("Windows PE (MZ), not ELF")
	}
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("not ELF: %w", err)
	}
	defer f.Close()

	if expectClass == "32" && f.Class != elf.ELFCLASS32 {
		return fmt.Errorf("class %s want ELFCLASS32", f.Class)
	}
	if expectClass == "64" && f.Class != elf.ELFCLASS64 {
		return fmt.Errorf("class %s want ELFCLASS64", f.Class)
	}
	if expectEndian == "le" && f.Data != elf.ELFDATA2LSB {
		return fmt.Errorf("endian %s want LSB", f.Data)
	}
	if expectEndian == "be" && f.Data != elf.ELFDATA2MSB {
		return fmt.Errorf("endian %s want MSB", f.Data)
	}
	if expectMachine == "mips" && f.Machine != emMIPS && f.Machine != elf.EM_MIPS {
		return fmt.Errorf("machine %s want EM_MIPS", f.Machine)
	}

	dynamic := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_DYNAMIC {
			dynamic = true
			break
		}
	}
	fmt.Printf("elf class=%s data=%s machine=%s type=%s dynamic=%v\n", f.Class, f.Data, f.Machine, f.Type, dynamic)
	return nil
}
