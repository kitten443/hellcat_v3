package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ParseHy2 converts a hysteria2:// / hy2:// link into Xray's Hysteria 2
// outbound. Salamander obfuscation is mapped to Xray's finalmask; obfs modes
// that Xray does not implement are rejected instead of producing a node that
// cannot connect.
func ParseHy2(rawURL string) (*OutboundConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Hysteria2 URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "hysteria2") && !strings.EqualFold(u.Scheme, "hy2") {
		return nil, fmt.Errorf("not a hysteria2:// link")
	}
	host := u.Hostname()
	if err := validateHost(host); err != nil {
		return nil, fmt.Errorf("Hysteria2: %w", err)
	}

	q := u.Query()
	portRaw := u.Port()
	if portRaw == "" {
		// Hysteria2 port hopping: mport=443,8443. Xray connects to one port,
		// so use the first entry as the primary port.
		portRaw = firstCSV(q.Get("mport"))
	}
	port, err := parsePort(portRaw, 443)
	if err != nil {
		return nil, fmt.Errorf("Hysteria2: %w", err)
	}

	finalMask, err := hysteriaFinalMask(q)
	if err != nil {
		return nil, fmt.Errorf("Hysteria2: %w", err)
	}

	auth := ""
	if u.User != nil {
		auth = u.User.Username()
		if extra, ok := u.User.Password(); ok {
			auth += ":" + extra
		}
	}

	pcs := queryValue(q, "pcs", "pinSHA256", "pinnedPeerCertSha256")
	vcn := queryValue(q, "vcn", "verifyPeerCertByName")
	insecure := boolValue(q, "insecure", "allowInsecure")

	alpn := alpnList(queryValue(q, "alpn"))
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}

	tls := &TlsConfig{
		ServerName:           deriveServerName(queryValue(q, "sni"), "", host),
		AllowInsecure:        insecure,
		Alpn:                 alpn,
		Fingerprint:          defaultString(queryValue(q, "fp"), "chrome"),
		PinnedPeerCertSha256: pcs,
		VerifyPeerCertByName: vcn,
	}
	if tls.PinnedPeerCertSha256 != "" || tls.VerifyPeerCertByName != "" {
		tls.AllowInsecure = false
	}

	stream := &StreamSetting{
		Network:          "hysteria",
		Security:         "tls",
		TlsSettings:      tls,
		HysteriaSettings: &HysteriaStreamSettings{Version: 2, Auth: auth},
		FinalMask:        finalMask,
		SocketOpt:        defaultSocketOpt(),
	}

	settings := HysteriaClientSettings{
		Version: 2,
		Address: host,
		Port:    port,
	}
	return newOutbound("hysteria", settings, stream), nil
}

// ParseTuic reports TUIC links explicitly. Xray-core has no TUIC outbound, so
// keeping such links would only create instances that fail to start.
func ParseTuic(rawURL string) (*OutboundConfig, error) {
	if !strings.HasPrefix(strings.ToLower(rawURL), "tuic://") {
		return nil, fmt.Errorf("not a tuic:// link")
	}
	return nil, fmt.Errorf("tuic:// is not supported: Xray-core has no TUIC outbound (use a sing-box based client for TUIC links)")
}

// hysteriaFinalMask converts `fm=` and Hysteria 2's Salamander obfuscation
// parameters into Xray's finalmask object. Older Xray versions do not support
// finalmask; links without obfs/fm are unaffected.
func hysteriaFinalMask(q url.Values) (json.RawMessage, error) {
	var finalMask json.RawMessage
	if raw := queryValue(q, "fm"); raw != "" {
		decoded, err := decodeJSONParam(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid fm parameter: %w", err)
		}
		finalMask = decoded
	}

	obfs := strings.ToLower(strings.TrimSpace(q.Get("obfs")))
	switch obfs {
	case "", "none":
		return finalMask, nil
	case "salamander":
		password := queryValue(q, "obfs-password", "obfsPassword")
		if password == "" {
			return nil, fmt.Errorf("obfs=salamander requires obfs-password")
		}
		return appendSalamanderMask(finalMask, password)
	default:
		return nil, fmt.Errorf("unsupported obfs %q (only salamander is supported)", obfs)
	}
}
