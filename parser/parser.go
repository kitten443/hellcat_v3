package parser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// Parse converts one share link into an outbound configuration.
func Parse(rawURL string) (*OutboundConfig, error) {
	rawURL = strings.TrimSpace(strings.TrimPrefix(rawURL, "\ufeff"))
	if rawURL == "" {
		return nil, fmt.Errorf("empty link")
	}

	lower := strings.ToLower(rawURL)
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return ParseVLESS(rawURL)
	case strings.HasPrefix(lower, "vmess://"):
		return ParseVMess(rawURL)
	case strings.HasPrefix(lower, "ss://"):
		return ParseShadowsocks(rawURL)
	case strings.HasPrefix(lower, "trojan://"):
		return ParseTrojan(rawURL)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		return ParseHy2(rawURL)
	case strings.HasPrefix(lower, "tuic://"):
		return ParseTuic(rawURL)
	}
	return nil, fmt.Errorf("unsupported scheme (expected vless, vmess, ss, trojan, hysteria2 or hy2)")
}

// queryValue returns the first non-empty value among the given keys.
func queryValue(q url.Values, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(q.Get(key)); v != "" {
			return v
		}
	}
	return ""
}

func boolValue(q url.Values, keys ...string) bool {
	for _, key := range keys {
		if ok, parsed := parseBool(q.Get(key)); parsed {
			return ok
		}
	}
	return false
}

func parseBool(raw string) (value bool, ok bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	}
	return false, false
}

func alpnList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// firstCSV returns the first entry of a comma separated list. Share links
// sometimes carry multiple hosts, while Xray accepts a single Host header.
func firstCSV(raw string) string {
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			return part
		}
	}
	return ""
}

func parsePort(raw string, fallback int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d is out of range 1-65535", port)
	}
	return port, nil
}

func validateHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("missing server address")
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return fmt.Errorf("invalid server address %q", host)
	}
	return nil
}

func isIPAddress(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

// deriveServerName picks a sensible SNI/serverName when the link omits it.
// Priority: explicit sni -> transport host -> server address (if it is a
// domain name).
func deriveServerName(sni, transportHost, address string) string {
	if sni = strings.TrimSpace(sni); sni != "" {
		return sni
	}
	if host := firstCSV(transportHost); host != "" {
		return host
	}
	if address != "" && !isIPAddress(address) {
		return address
	}
	return ""
}

func normalizeNetwork(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "none", "tcp", "raw":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "grpc":
		return "grpc"
	case "xhttp", "splithttp":
		return "xhttp"
	case "httpupgrade":
		return "httpupgrade"
	case "kcp", "mkcp":
		return "kcp"
	case "http", "h2", "h3":
		return "http"
	case "quic":
		return "quic"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

// decodeBase64 accepts standard, URL-safe, padded and unpadded base64. Share
// links are produced by many different panels, so be permissive.
func decodeBase64(raw string) ([]byte, error) {
	s := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(raw))
	if s == "" {
		return nil, fmt.Errorf("empty base64 payload")
	}
	if strings.Contains(s, "%") {
		if unescaped, err := url.PathUnescape(s); err == nil {
			s = unescaped
		}
	}

	padded := s
	if rem := len(padded) % 4; rem != 0 {
		padded += strings.Repeat("=", 4-rem)
	}

	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(padded); err == nil && len(decoded) > 0 {
			return decoded, nil
		}
		if decoded, err := enc.DecodeString(strings.TrimRight(padded, "=")); err == nil && len(decoded) > 0 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 payload")
}

// decodeJSONParam passes an URL-encoded JSON object through to Xray. XHTTP
// links use `extra` for transport tuning; newer Xray versions understand the
// object as-is, so it is better to forward it than to whitelist a few keys.
func decodeJSONParam(raw string) (json.RawMessage, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if strings.Contains(raw, "%") {
		if unescaped, err := url.QueryUnescape(raw); err == nil {
			raw = unescaped
		}
	}
	if !json.Valid([]byte(raw)) {
		return nil, fmt.Errorf("invalid JSON in transport parameters")
	}
	return json.RawMessage(raw), nil
}

func defaultSocketOpt() SocketOpt {
	return SocketOpt{
		DomainStrategy: "UseIP",
		HappyEyeballs: &HappyEyeballs{
			Interleave:       2,
			MaxConcurrentTry: 4,
			PrioritizeIPv6:   false,
			TryDelayMs:       250,
		},
	}
}

func defaultMux() MuxConfig {
	return MuxConfig{Enabled: false, Concurrency: -1}
}

func newOutbound(protocol string, settings interface{}, stream *StreamSetting) *OutboundConfig {
	return &OutboundConfig{
		Tag:           "proxy",
		Protocol:      protocol,
		Mux:           defaultMux(),
		Settings:      settings,
		StreamSetting: stream,
	}
}
