package parser

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseVLESS parses the standard vless:// share link format, including
// TCP/WS/gRPC/XHTTP/HTTPUpgrade/mKCP transports and TLS/REALITY security.
func ParseVLESS(rawURL string) (*OutboundConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid VLESS URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "vless") {
		return nil, fmt.Errorf("not a vless:// link")
	}
	if u.User == nil {
		return nil, fmt.Errorf("VLESS UUID is missing")
	}
	uuid := strings.TrimSpace(u.User.Username())
	if uuid == "" {
		return nil, fmt.Errorf("VLESS UUID is missing")
	}
	host := u.Hostname()
	if err := validateHost(host); err != nil {
		return nil, fmt.Errorf("VLESS: %w", err)
	}
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return nil, fmt.Errorf("VLESS: %w", err)
	}

	q := u.Query()
	params := streamParamsFromQuery(q)
	if params.Security == "" {
		params.Security = "none"
	}
	stream, err := buildStreamSettings(params, host)
	if err != nil {
		return nil, fmt.Errorf("VLESS: %w", err)
	}

	flow := strings.ToLower(strings.TrimSpace(q.Get("flow")))
	if flow != "" {
		switch flow {
		case "xtls-rprx-vision", "xtls-rprx-vision-udp443":
		default:
			return nil, fmt.Errorf("VLESS: unsupported flow %q", flow)
		}
		if stream.Network != "tcp" || (stream.Security != "tls" && stream.Security != "reality") {
			return nil, fmt.Errorf("VLESS: flow %q requires tcp + tls/reality (got %s + %s)",
				flow, stream.Network, stream.Security)
		}
	}

	encryption := strings.TrimSpace(q.Get("encryption"))
	if encryption == "" {
		encryption = "none"
	}

	settings := VnextSettings{
		Vnext: []Vnext{{
			Address: host,
			Port:    port,
			Users: []User{{
				Id:         uuid,
				Encryption: encryption,
				Flow:       flow,
				Level:      8,
			}},
		}},
	}

	return newOutbound("vless", settings, stream), nil
}
