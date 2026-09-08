package subscription

// Level is parser / observation status. It is not a hardware capability flag.
type Level string

const (
	Supported      Level = "SUPPORTED"
	Partial        Level = "PARTIAL"
	NotImplemented Level = "NOT_IMPLEMENTED"
	NotObserved    Level = "NOT_OBSERVED"
)

// SchemeSupport describes one share or JSON shape.
type SchemeSupport struct {
	Scheme  string
	Parser  Level
	Runtime Level
	Notes   string
}

// ParserSupport is the architecture table for this package.
func ParserSupport() []SchemeSupport {
	return []SchemeSupport{
		{
			Scheme:  "vless://",
			Parser:  Supported,
			Runtime: NotObserved,
			Notes:   "public VLESS share URI (uuid@host:port?query#remark)",
		},
		{
			Scheme:  "vmess://",
			Parser:  Supported,
			Runtime: NotObserved,
			Notes:   "v2rayN base64 JSON and public uuid@host URI form",
		},
		{
			Scheme:  "trojan://",
			Parser:  Supported,
			Runtime: NotObserved,
			Notes:   "public Trojan share URI (password@host:port?query#remark)",
		},
		{
			Scheme:  "ss://",
			Parser:  Supported,
			Runtime: NotObserved,
			Notes:   "SIP002 userinfo and legacy base64 method:password@host:port",
		},
		{
			Scheme:  "json-uri-array",
			Parser:  Partial,
			Runtime: NotObserved,
			Notes:   "JSON array of share-URI strings",
		},
		{
			Scheme:  "json-outbound",
			Parser:  Partial,
			Runtime: NotObserved,
			Notes:   "Xray-like outbound objects with public field names only",
		},
		{
			Scheme:  "hysteria2://",
			Parser:  NotImplemented,
			Runtime: NotObserved,
			Notes:   "scheme observed in APK strings; no parser in this wave",
		},
		{
			Scheme:  "hy2://",
			Parser:  NotImplemented,
			Runtime: NotObserved,
			Notes:   "alias observed with Hysteria2; no parser in this wave",
		},
		{
			Scheme:  "wireguard",
			Parser:  NotImplemented,
			Runtime: NotObserved,
			Notes:   "name observed in APK strings; no share-URI parser here",
		},
		{
			Scheme:  "provider-json",
			Parser:  NotObserved,
			Runtime: NotObserved,
			Notes:   "unknown JSON is rejected; proprietary envelopes are not guessed",
		},
	}
}
