package protocols

// Status values. SUPPORTED is reserved for hardware PASS (not this wave).
const (
	StatusNotRun      = "NOT RUN"
	StatusUnsupported = "UNSUPPORTED"
)

// Combination is one generator/runtime cell.
type Combination struct {
	Protocol  string
	Transport string
	Security  string
	Generated bool
	XrayTest  string // windows `xray run -test` in this package's sister tests; never hardware
	QEMU      string
	Hardware  string
	Notes     string
}

// P0Matrix is VLESS + TLS/REALITY. Transports tcp/ws/grpc/xhttp are generated
// because fixtures exist; they are not SUPPORTED on KN-1011.
func P0Matrix() []Combination {
	notes := "R4 generator emits this combination. Do not treat as SUPPORTED until KN-1011 hardware PASS."
	rows := []Combination{
		{Protocol: "vless", Transport: "tcp", Security: "tls", Generated: true, Notes: notes},
		{Protocol: "vless", Transport: "tcp", Security: "reality", Generated: true, Notes: notes},
		{Protocol: "vless", Transport: "ws", Security: "tls", Generated: true, Notes: notes},
		{Protocol: "vless", Transport: "grpc", Security: "tls", Generated: true, Notes: notes},
		{Protocol: "vless", Transport: "xhttp", Security: "tls", Generated: true, Notes: notes},
	}
	for i := range rows {
		rows[i].XrayTest = StatusNotRun
		rows[i].QEMU = StatusNotRun
		rows[i].Hardware = StatusNotRun
	}
	return rows
}
