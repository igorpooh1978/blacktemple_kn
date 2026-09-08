// Package connection is the R4-I application bridge:
//
//	profiles/keys/subscription → connection → xray → supervisor
//
// HTTP handlers must not call subscription parse or os/exec directly.
package connection
