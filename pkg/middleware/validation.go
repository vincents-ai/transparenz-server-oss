// Copyright (c) 2026 Vincent Palmer. All rights reserved.
//
// This software is proprietary and confidential. Unauthorized use,
// redistribution, or modification is strictly prohibited.
// See LICENSE.md for terms.
package middleware

import "net"

// IsPrivateIP checks whether the given hostname resolves to a private, loopback,
// or link-local IP address. Returns true if the host cannot be resolved or
// resolves to any RFC 1918/RFC 4193/RFC 3927/RFC 5735 address.
//
// This is used for SSRF prevention: outbound requests (e.g., to OTel collectors,
// ENISA/CSIRT endpoints) must not target private network addresses.
func IsPrivateIP(host string) bool {
	ips, err := net.LookupIP(host)
	if err != nil {
		return true // fail closed: unresolvable hosts are treated as private
	}
	privateNets := []string{
		"127.0.0.0/8",   // loopback
		"10.0.0.0/8",    // RFC 1918
		"172.16.0.0/12", // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local
		"0.0.0.0/8",     // "this" network
		"::1/128",       // IPv6 loopback
		"fc00::/7",      // IPv6 unique-local (RFC 4193)
		"fe80::/10",     // IPv6 link-local
	}
	for _, ip := range ips {
		for _, cidr := range privateNets {
			_, network, _ := net.ParseCIDR(cidr)
			if network != nil && network.Contains(ip) {
				return true
			}
		}
	}
	return false
}
