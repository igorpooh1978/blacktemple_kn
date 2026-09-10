package subscription

import (
	"encoding/json"
	"strings"
)

type androidFile struct {
	Outbounds []androidOutbound `json:"outbounds"`
}

type androidOutbound struct {
	Protocol       string                `json:"protocol"`
	Tag            string                `json:"tag"`
	Settings       androidSettings       `json:"settings"`
	StreamSettings androidStreamSettings `json:"streamSettings"`
}

type androidSettings struct {
	Vnext []androidVnext `json:"vnext"`
}

type androidVnext struct {
	Address string        `json:"address"`
	Port    int           `json:"port"`
	Users   []androidUser `json:"users"`
}

type androidUser struct {
	ID         string `json:"id"`
	Flow       string `json:"flow"`
	Encryption string `json:"encryption"`
}

type androidStreamSettings struct {
	Network         string          `json:"network"`
	Security        string          `json:"security"`
	TLSSettings     *androidTLS     `json:"tlsSettings"`
	WSSettings      *androidWS      `json:"wsSettings"`
	XHTTPSettings   *androidXHTTP   `json:"xhttpSettings"`
	RealitySettings json.RawMessage `json:"realitySettings"`
}

type androidTLS struct {
	ServerName    string `json:"serverName"`
	Fingerprint   string `json:"fingerprint"`
	AllowInsecure bool   `json:"allowInsecure"`
}

type androidWS struct {
	Path    string            `json:"path"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
}

type androidXHTTP struct {
	Path string `json:"path"`
	Host string `json:"host"`
	Mode string `json:"mode"`
}

// ParseXrayConfig extracts normalized VLESS candidates from an Android StartLoop JSON.
// Reality outbounds are skipped. Secrets are not logged.
func ParseXrayConfig(raw []byte) (Result, error) {
	var file androidFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return Result{}, errParse("json")
	}
	var entries []ParsedShare
	seen := map[string]struct{}{}
	skipped := 0
	for _, o := range file.Outbounds {
		if !strings.EqualFold(o.Protocol, "vless") {
			skipped++
			continue
		}
		sec := normalizeSecurity(o.StreamSettings.Security)
		if sec == "reality" {
			skipped++
			continue
		}
		if len(o.Settings.Vnext) == 0 || len(o.Settings.Vnext[0].Users) == 0 {
			skipped++
			continue
		}
		vn := o.Settings.Vnext[0]
		id := strings.TrimSpace(vn.Users[0].ID)
		if id == "" || vn.Address == "" || vn.Port < 1 {
			skipped++
			continue
		}
		transport := normalizeTransport(o.StreamSettings.Network)
		params := ConnectionParams{
			Flow: vn.Users[0].Flow,
		}
		if o.StreamSettings.TLSSettings != nil {
			params.SNI = o.StreamSettings.TLSSettings.ServerName
			params.Fingerprint = o.StreamSettings.TLSSettings.Fingerprint
			params.AllowInsecure = o.StreamSettings.TLSSettings.AllowInsecure
		}
		switch transport {
		case "ws":
			if o.StreamSettings.WSSettings != nil {
				params.Path = o.StreamSettings.WSSettings.Path
				params.Host = o.StreamSettings.WSSettings.Host
				if params.Host == "" && o.StreamSettings.WSSettings.Headers != nil {
					params.Host = o.StreamSettings.WSSettings.Headers["Host"]
					if params.Host == "" {
						params.Host = o.StreamSettings.WSSettings.Headers["host"]
					}
				}
			}
		case "xhttp":
			if o.StreamSettings.XHTTPSettings != nil {
				params.Path = o.StreamSettings.XHTTPSettings.Path
				params.Host = o.StreamSettings.XHTTPSettings.Host
				params.Mode = o.StreamSettings.XHTTPSettings.Mode
			}
		}
		remark := strings.TrimSpace(o.Tag)
		e := ParsedShare{
			Protocol:   "vless",
			Host:       vn.Address,
			Port:       vn.Port,
			Transport:  transport,
			Security:   sec,
			Remark:     remark,
			FieldNames: []string{"protocol", "network", "security"},
			Params:     params,
			secret:     secret(id),
		}
		e.StableID = stableID(e.Protocol, e.Host, e.Port, e.Transport, e.Security, e.Remark)
		if _, ok := seen[e.StableID]; ok {
			skipped++
			continue
		}
		seen[e.StableID] = struct{}{}
		entries = append(entries, e)
	}
	return Result{
		Entries:    entries,
		Skipped:    skipped,
		Encoding:   "json",
		Format:     "xray-startloop",
		FieldNames: []string{"protocol", "network", "security"},
	}, nil
}
