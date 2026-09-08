package xray

// Pin is third_party/xray.lock.json.
type Pin struct {
	SchemaVersion        int                  `json:"schemaVersion"`
	Name                 string               `json:"name"`
	License              string               `json:"license"`
	Upstream             string               `json:"upstream"`
	Version              string               `json:"version"`
	Tag                  string               `json:"tag"`
	VerificationDate     string               `json:"verificationDate"`
	HardwareVerification HardwareVerification `json:"hardwareVerification"`
	Notes                string               `json:"notes"`
	Targets              map[string]PinTarget `json:"targets"`
	StableAutoUpdate     bool                 `json:"stableAutoUpdate"`
}

// HardwareVerification values for this wave are NOT RUN only.
type HardwareVerification struct {
	QEMU   string `json:"qemu"`
	KN1011 string `json:"kn-1011"`
}

// PinTarget is one official GitHub zip.
type PinTarget struct {
	ZipURL      string `json:"zipUrl"`
	ZipSHA256   string `json:"zipSha256"`
	BinaryInZip string `json:"binaryInZip"`
	IPKArch     string `json:"ipkArch"`
}
