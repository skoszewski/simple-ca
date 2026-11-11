// MIT License
//
// Copyright (c) 2026 Slawomir Koszewski
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package simpleca

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// KebabCaseRE matches a kebab-case name, the form of the names of issuing CAs, certificate types
// and tokens: words of lower-case letters and digits joined by single hyphens, such as web-server.
var KebabCaseRE = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// durationUnits are the units of a duration, largest first: y of 365 days, m of 30 days, d of 24
// hours and h; a number without a unit is minutes.
var durationUnits = []struct {
	unit string
	size time.Duration
}{
	{"y", 365 * 24 * time.Hour},
	{"m", 30 * 24 * time.Hour},
	{"d", 24 * time.Hour},
	{"h", time.Hour},
}

// durationRE matches a duration: a whole number, then optional spaces and one unit.
var durationRE = regexp.MustCompile(`^([0-9]+)\s*([ymdh]?)$`)

// ParseDuration returns the duration s gives, such as 30 for 30 minutes, 8h, 180d, 6m or 1y.
func ParseDuration(s string) (time.Duration, error) {
	m := durationRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("'%s' is not a duration such as 30 (minutes), 8h, 180d, 6m or 1y", s)
	}
	size := time.Minute
	for _, u := range durationUnits {
		if u.unit == m[2] {
			size = u.size
		}
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || n > math.MaxInt64/int64(size) {
		return 0, fmt.Errorf("'%s' is longer than a duration can be", s)
	}
	return time.Duration(n) * size, nil
}

// DurationText returns d as ParseDuration reads it, in the largest unit holding it whole, or in
// minutes, a part of a minute rounded: 1y, 6m, 2d, 8h, 15.
func DurationText(d time.Duration) string {
	d = d.Round(time.Minute)
	for _, u := range durationUnits {
		if d >= u.size && d%u.size == 0 {
			return strconv.FormatInt(int64(d/u.size), 10) + u.unit
		}
	}
	return strconv.FormatInt(int64(d/time.Minute), 10)
}

// hostnameRE matches a hostname or an FQDN: labels of letters, digits and hyphens.
var hostnameRE = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ParseIP returns s as an IPv4 or IPv6 address without a zone.
func ParseIP(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	return addr, err == nil && addr.Zone() == ""
}

// ParsePrefix returns s, an IPv4 or IPv6 address or prefix without a zone, as a masked prefix; an
// address is the prefix of that address alone.
func ParsePrefix(s string) (netip.Prefix, bool) {
	if addr, ok := ParseIP(s); ok {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	prefix, err := netip.ParsePrefix(s)
	return prefix.Masked(), err == nil && prefix.Addr().Zone() == ""
}

// IsHostname reports whether s is a hostname or an FQDN whose last label is not all digits, and
// neither an IP address nor an OID.
func IsHostname(s string) bool {
	if _, ok := ParseIP(s); ok {
		return false
	}
	if _, err := x509.ParseOID(s); err == nil {
		return false
	}
	last := s[strings.LastIndex(s, ".")+1:]
	return len(s) <= 253 && hostnameRE.MatchString(s) && strings.Trim(last, "0123456789") != ""
}

// RandomID returns 16 random bytes in base64url.
func RandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
