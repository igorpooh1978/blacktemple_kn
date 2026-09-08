package subscription

import (
	"context"
	"net/http"
)

// ProbeResult is a sanitized classification of a subscription fetch.
// It never includes share URIs, UUIDs, or passwords.
type ProbeResult struct {
	ContentType    string
	Encoding       string
	Format         string
	EntryCount     int
	DuplicateCount int
	Skipped        int
	Protocols      map[string]int
	Transports     []string
	Securities     []string
	FieldNames     []string
	CountryHints   []string
	UserInfoHeader bool
}

func (p ProbeResult) String() string {
	return "ProbeResult{ContentType:" + p.ContentType +
		" Encoding:" + p.Encoding +
		" Format:" + p.Format +
		" Entries:" + itoa(p.EntryCount) + "}"
}

func (p ProbeResult) GoString() string { return p.String() }

// Probe fetches and classifies a subscription. Intended for tests and
// local research traces (structural fields only).
func Probe(ctx context.Context, client *http.Client, rawURL string) (ProbeResult, error) {
	fetched, err := Fetch(ctx, client, rawURL)
	if err != nil {
		return ProbeResult{}, err
	}
	parsed, err := Parse(fetched.Body)
	if err != nil {
		return ProbeResult{
			ContentType:    fetched.ContentType,
			UserInfoHeader: fetched.UserInfoPresent,
		}, err
	}
	return Classify(fetched, parsed), nil
}

// Classify builds a sanitized probe view from an already parsed body.
func Classify(fetched Fetched, parsed Result) ProbeResult {
	protocols := map[string]int{}
	tset := map[string]struct{}{}
	sset := map[string]struct{}{}
	cset := map[string]struct{}{}
	for _, e := range parsed.Entries {
		protocols[e.Protocol]++
		if e.Transport != "" {
			tset[e.Transport] = struct{}{}
		}
		if e.Security != "" {
			sset[e.Security] = struct{}{}
		}
		if e.CountryHint != "" {
			cset[e.CountryHint] = struct{}{}
		}
	}
	return ProbeResult{
		ContentType:    fetched.ContentType,
		Encoding:       parsed.Encoding,
		Format:         parsed.Format,
		EntryCount:     len(parsed.Entries),
		DuplicateCount: parsed.DuplicateCount,
		Skipped:        parsed.Skipped,
		Protocols:      protocols,
		Transports:     sortedKeys(tset),
		Securities:     sortedKeys(sset),
		FieldNames:     parsed.FieldNames,
		CountryHints:   sortedKeys(cset),
		UserInfoHeader: fetched.UserInfoPresent,
	}
}
