package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
)

func main() {
	in := flag.String("in", "", "Android StartLoop JSON path (gitignored)")
	dataDir := flag.String("data-dir", "", "profiles.json data directory")
	name := flag.String("name", "resolved", "profile name if created")
	profileID := flag.String("profile-id", "", "existing profile id; empty uses active or creates")
	flag.Parse()
	if *in == "" || *dataDir == "" {
		fmt.Fprintln(os.Stderr, "usage: resolvedimport -in FILE -data-dir DIR")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read_failed")
		os.Exit(1)
	}
	svc := profiles.New(profiles.Config{DataDir: *dataDir})
	id := *profileID
	if id == "" {
		id = svc.ActiveID()
	}
	if id == "" {
		p, err := svc.CreateBlackKeyShell(*name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create_failed")
			os.Exit(1)
		}
		id = p.ID
	}
	sum, err := svc.ImportResolvedJSON(id, raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import_failed")
		os.Exit(1)
	}
	if err := svc.SetActive(id); err != nil {
		fmt.Fprintln(os.Stderr, "activate_failed")
		os.Exit(1)
	}
	fmt.Printf("profile_id_len=%d\n", len(id))
	fmt.Printf("candidate_count=%d\n", sum.CandidateCount)
	fmt.Printf("ws_tls_count=%d\n", sum.WSTLSCount)
	fmt.Printf("xhttp_tls_count=%d\n", sum.XHTTPTLSCount)
	fmt.Printf("uuid_valid_count=%d\n", sum.UUIDValidCount)
	fmt.Printf("reality_count=%d\n", sum.RealityCount)
	fmt.Printf("invalid_skipped=%d\n", sum.InvalidSkipped)
}
