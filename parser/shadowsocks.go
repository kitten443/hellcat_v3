package parser

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ParseShadowsocks supports SIP002 links (base64 or plain userinfo) as well as
// the old ss://<base64> form. SIP003 plugins (obfs-local, v2ray-plugin) are
// intentionally rejected: Xray-core does not implement them.
func ParseShadowsocks(rawURL string) (*OutboundConfig, error) {
	if !strings.HasPrefix(strings.ToLower(rawURL), "ss://") {
		return nil, fmt.Errorf("not an ss:// link")
	}
	rest := rawURL[len("ss://"):]
	if idx := strings.Index(rest, "#"); idx >= 0 {
		rest = rest[:idx]
	}

	mainPart := rest
	if idx := strings.Index(rest, "?"); idx >= 0 {
		mainPart = rest[:idx]
		if plugin := strings.TrimSpace(mustParseQuery(rest[idx+1:]).Get("plugin")); plugin != "" {
			return nil, fmt.Errorf("shadowsocks plugin %q is not supported by Xray-core", plugin)
		}
	}

	var method, password, host, portRaw string

	if at := strings.LastIndex(mainPart, "@"); at >= 0 {
		userinfo := mainPart[:at]
		hostport := mainPart[at+1:]

		decoded, err := decodeBase64(userinfo)
		if err == nil && bytes.Contains(decoded, []byte(":")) {
			method, password, err = splitMethodPassword(string(decoded))
			if err != nil {
				return nil, fmt.Errorf("shadowsocks: %w", err)
			}
		} else {
			plain, err := url.PathUnescape(userinfo)
			if err != nil {
				plain = userinfo
			}
			method, password, err = splitMethodPassword(plain)
			if err != nil {
				return nil, fmt.Errorf("shadowsocks: %w", err)
			}
		}

		host, portRaw, err = net.SplitHostPort(hostport)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: invalid host:port %q: %w", hostport, err)
		}
	} else {
		decoded, err := decodeBase64(mainPart)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: %w", err)
		}
		legacy := string(decoded)
		at := strings.LastIndex(legacy, "@")
		if at <= 0 {
			return nil, fmt.Errorf("shadowsocks: invalid legacy link (missing credentials or host)")
		}
		method, password, err = splitMethodPassword(legacy[:at])
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: %w", err)
		}
		host, portRaw, err = net.SplitHostPort(legacy[at+1:])
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: invalid host:port %q: %w", legacy[at+1:], err)
		}
	}

	if err := validateHost(host); err != nil {
		return nil, fmt.Errorf("shadowsocks: %w", err)
	}
	port, err := parsePort(portRaw, 0)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("shadowsocks: invalid port %q", portRaw)
	}
	method, err = normalizeSSMethod(method)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, fmt.Errorf("shadowsocks: empty password")
	}

	settings := ServerSettings{
		Servers: []ServerEntry{{
			Address:  host,
			Port:     port,
			Method:   method,
			Password: password,
		}},
	}
	return newOutbound("shadowsocks", settings, nil), nil
}

func splitMethodPassword(raw string) (method, password string, err error) {
	idx := strings.Index(raw, ":")
	if idx <= 0 {
		return "", "", fmt.Errorf("invalid credentials (expected method:password)")
	}
	return strings.TrimSpace(raw[:idx]), raw[idx+1:], nil
}

func normalizeSSMethod(raw string) (string, error) {
	method := strings.ToLower(strings.TrimSpace(raw))
	switch method {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return "aes-128-gcm", nil
	case "aes-256-gcm", "aead_aes_256_gcm":
		return "aes-256-gcm", nil
	case "chacha20-poly1305", "chacha20-ietf-poly1305", "aead_chacha20_poly1305":
		return "chacha20-poly1305", nil
	case "xchacha20-poly1305", "xchacha20-ietf-poly1305", "aead_xchacha20_poly1305":
		return "xchacha20-poly1305", nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return method, nil
	}
	return "", fmt.Errorf("shadowsocks: unsupported cipher %q", raw)
}

func mustParseQuery(raw string) url.Values {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return url.Values{}
	}
	return values
}
