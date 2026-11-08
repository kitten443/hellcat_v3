package parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// jsonInt accepts both JSON numbers and quoted numbers. VMess payloads are
// produced by many clients and both forms are common.
type jsonInt int

func (n *jsonInt) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(data)), `"`))
	if raw == "" || raw == "null" {
		*n = 0
		return nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fmt.Errorf("invalid number %q", raw)
	}
	*n = jsonInt(value)
	return nil
}

// jsonBool accepts booleans as well as the "1"/"0"/"true"/"false" strings
// emitted by some panel exporters.
type jsonBool bool

func (b *jsonBool) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(data)), `"`))
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		*b = true
	case "0", "false", "no", "off", "", "null":
		*b = false
	default:
		return fmt.Errorf("invalid boolean %q", raw)
	}
	return nil
}

type vmessLink struct {
	V             string   `json:"v"`
	Ps            string   `json:"ps"`
	Add           string   `json:"add"`
	Port          jsonInt  `json:"port"`
	Id            string   `json:"id"`
	Aid           jsonInt  `json:"aid"`
	Scy           string   `json:"scy"`
	Net           string   `json:"net"`
	Type          string   `json:"type"`
	Host          string   `json:"host"`
	Path          string   `json:"path"`
	Tls           string   `json:"tls"`
	Sni           string   `json:"sni"`
	Alpn          string   `json:"alpn"`
	Fp            string   `json:"fp"`
	AllowInsecure jsonBool `json:"allowInsecure"`
}

// ParseVMess understands both formats used in the wild:
//   - the classic vmess://<base64(JSON)> payload
//   - the VMessAEAD URI format vmess://uuid@host:port?...#tag
func ParseVMess(rawURL string) (*OutboundConfig, error) {
	if !strings.HasPrefix(strings.ToLower(rawURL), "vmess://") {
		return nil, fmt.Errorf("not a vmess:// link")
	}
	rest := rawURL[len("vmess://"):]
	detect := rest
	if idx := strings.Index(detect, "#"); idx >= 0 {
		detect = detect[:idx]
	}
	if strings.Contains(detect, "@") {
		return parseVMessURI(rawURL)
	}
	return parseVMessJSON(rest)
}

func parseVMessJSON(payload string) (*OutboundConfig, error) {
	if idx := strings.Index(payload, "#"); idx >= 0 {
		payload = payload[:idx]
	}
	decoded, err := decodeBase64(payload)
	if err != nil {
		return nil, fmt.Errorf("VMess: %w", err)
	}

	var v vmessLink
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, fmt.Errorf("VMess: invalid JSON payload: %w", err)
	}

	host := strings.TrimSpace(v.Add)
	if err := validateHost(host); err != nil {
		return nil, fmt.Errorf("VMess: %w", err)
	}
	port := int(v.Port)
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("VMess: invalid port %d", port)
	}
	uuid := strings.TrimSpace(v.Id)
	if uuid == "" {
		return nil, fmt.Errorf("VMess: UUID is missing")
	}

	params := streamParams{
		Network:       v.Net,
		Security:      strings.ToLower(strings.TrimSpace(v.Tls)),
		Host:          firstCSV(v.Host),
		Path:          v.Path,
		ServiceName:   v.Path,
		Authority:     firstCSV(v.Host),
		HeaderType:    v.Type,
		Alpn:          alpnList(v.Alpn),
		SNI:           v.Sni,
		Fingerprint:   v.Fp,
		AllowInsecure: bool(v.AllowInsecure),
	}
	if params.Security == "" {
		params.Security = "none"
	}
	stream, err := buildStreamSettings(params, host)
	if err != nil {
		return nil, fmt.Errorf("VMess: %w", err)
	}

	security := strings.TrimSpace(v.Scy)
	if security == "" {
		security = "auto"
	}

	settings := VMessSettings{
		Vnext: []VMessVnext{{
			Address: host,
			Port:    port,
			Users: []VMessUser{{
				Id:       uuid,
				AlterId:  int(v.Aid),
				Security: security,
			}},
		}},
	}

	return newOutbound("vmess", settings, stream), nil
}

func parseVMessURI(rawURL string) (*OutboundConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid VMess URL: %w", err)
	}
	if u.User == nil {
		return nil, fmt.Errorf("VMess UUID is missing")
	}
	uuid := strings.TrimSpace(u.User.Username())
	if uuid == "" {
		return nil, fmt.Errorf("VMess UUID is missing")
	}
	host := u.Hostname()
	if err := validateHost(host); err != nil {
		return nil, fmt.Errorf("VMess: %w", err)
	}
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return nil, fmt.Errorf("VMess: %w", err)
	}

	q := u.Query()
	params := streamParamsFromQuery(q)
	if params.Security == "" {
		if tls := strings.ToLower(q.Get("tls")); tls == "tls" || tls == "1" || tls == "true" {
			params.Security = "tls"
		} else {
			params.Security = "none"
		}
	}
	if params.ServiceName == "" && normalizeNetwork(params.Network) == "grpc" {
		params.ServiceName = params.Path
	}
	if params.Authority == "" && normalizeNetwork(params.Network) == "grpc" {
		params.Authority = params.Host
	}
	stream, err := buildStreamSettings(params, host)
	if err != nil {
		return nil, fmt.Errorf("VMess: %w", err)
	}

	security := strings.TrimSpace(queryValue(q, "encryption", "scy"))
	if security == "" {
		security = "auto"
	}

	settings := VMessSettings{
		Vnext: []VMessVnext{{
			Address: host,
			Port:    port,
			Users: []VMessUser{{
				Id:       uuid,
				AlterId:  0,
				Security: security,
			}},
		}},
	}

	return newOutbound("vmess", settings, stream), nil
}
