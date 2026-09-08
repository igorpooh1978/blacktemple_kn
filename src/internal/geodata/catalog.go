package geodata

// Catalog is a geosite tag list. A later remote catalog can replace BuiltinCatalog.
type Catalog interface {
	Tags() []Tag
}

// Tag is a conventional v2ray/Xray geosite identifier (domain-list-community).
type Tag struct {
	ID     string
	Origin string
}

// BuiltinCatalog is a small, ordered set of well-known geosite names.
// It is not a copy of APK geosite_tags.json and is not derived from a .dat parse.
type BuiltinCatalog struct{}

// builtinTags is the source-of-truth order (no map iteration).
//
// Justification (v2fly/domain-list-community conventional names, also present
// in typical v2ray/Xray geosite.dat builds):
//   - youtube, telegram, google, discord, netflix: standalone list files
//   - category-ads-all: standard aggregate ads category in geosite.dat
var builtinTags = []Tag{
	{ID: "youtube", Origin: "v2fly/domain-list-community"},
	{ID: "telegram", Origin: "v2fly/domain-list-community"},
	{ID: "google", Origin: "v2fly/domain-list-community"},
	{ID: "discord", Origin: "v2fly/domain-list-community"},
	{ID: "netflix", Origin: "v2fly/domain-list-community"},
	{ID: "category-ads-all", Origin: "v2fly/domain-list-community"},
}

func (BuiltinCatalog) Tags() []Tag {
	out := make([]Tag, len(builtinTags))
	copy(out, builtinTags)
	return out
}
