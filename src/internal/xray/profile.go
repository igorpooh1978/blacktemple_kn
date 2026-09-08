package xray

// Profile is the frozen XrayProfileModel (contracts/schemas/xray-profile.schema.json).
// Extra wire fields live in ConfigSecrets and OutboundParams — see .ai/reports/C-contract-gap.md.
type Profile struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Protocol  string `json:"protocol"`
	Server    string `json:"server,omitempty"`
	Port      int    `json:"port,omitempty"`
	Transport string `json:"transport,omitempty"`
	Security  string `json:"security,omitempty"`
	Country   string `json:"country,omitempty"`
}
