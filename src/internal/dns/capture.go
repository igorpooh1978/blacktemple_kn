package dns

// DNSCaptureEngine is a reserved seam for a future DNS intercept engine.
// This wave does not intercept :53, does not REDIRECT/TPROXY DNS, and does
// not change ndnproxy or Keenetic DNS settings.
type DNSCaptureEngine struct{}
