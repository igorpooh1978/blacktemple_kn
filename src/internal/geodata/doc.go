// Package geodata manages GeoIP/GeoSite file lifecycle on disk.
//
// Sets are immutable directories under geodata/sets/<id>/. Active and previous
// are selected by an atomically replaced state.json pointer. Rollback swaps
// pointer IDs and does not move .dat files.
//
// It does not parse .dat into RAM, does not bundle geoip.dat/geosite.dat,
// does not copy APK geosite_tags.json, and does not spawn Xray.
// Production conceptual root is DefaultDataDir; tests must pass a temp DataDir.
package geodata

// DefaultDataDir is the on-router data root. Managers must still be constructed
// with an explicit DataDir; tests never use this constant as a live path.
const DefaultDataDir = "/opt/blacktemple-kn/data"
