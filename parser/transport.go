package parser

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// streamParams is the protocol-independent description of a transport parsed
// from a share link. VLESS, VMess and Trojan links all map onto it.
type streamParams struct {
	Network       string
	Security      string
	Host          string
	Path          string
	ServiceName   string
	Authority     string
	Mode          string
	Extra         json.RawMessage
	HeaderType    string
	Alpn          []string
	SNI           string
	Fingerprint   string
	AllowInsecure bool
	PCS           string
	VCN           string
	ECH           string
	PublicKey     string
	ShortID       string
	SpiderX       string
	Mldsa65Verify string
	FinalMask     json.RawMessage
}

func streamParamsFromQuery(q url.Values) streamParams {
	security := strings.ToLower(queryValue(q, "security"))
	network := queryValue(q, "type", "network")

	var extra json.RawMessage
	// A malformed extra value is returned by buildStreamSettings through the
	// validating wrapper below; keeping the raw string here lets the caller
	// produce a link-specific error instead of silently dropping options.
	if raw := queryValue(q, "extra"); raw != "" {
		extra = json.RawMessage(raw)
	}

	return streamParams{
		Network:       network,
		Security:      security,
		Host:          firstCSV(queryValue(q, "host")),
		Path:          queryValue(q, "path"),
		ServiceName:   queryValue(q, "serviceName"),
		Authority:     queryValue(q, "authority"),
		Mode:          queryValue(q, "mode"),
		Extra:         extra,
		HeaderType:    queryValue(q, "headerType"),
		Alpn:          alpnList(queryValue(q, "alpn")),
		SNI:           queryValue(q, "sni"),
		Fingerprint:   queryValue(q, "fp", "fingerprint"),
		AllowInsecure: boolValue(q, "allowInsecure", "insecure"),
		PCS:           queryValue(q, "pcs", "pinnedPeerCertSha256"),
		VCN:           queryValue(q, "vcn", "verifyPeerCertByName"),
		ECH:           queryValue(q, "ech"),
		PublicKey:     queryValue(q, "pbk", "publicKey"),
		ShortID:       queryValue(q, "sid", "shortId"),
		SpiderX:       queryValue(q, "spx", "spiderX"),
		Mldsa65Verify: queryValue(q, "pqv", "mldsa65Verify"),
		FinalMask:     json.RawMessage(queryValue(q, "fm")),
	}
}

func buildStreamSettings(p streamParams, address string) (*StreamSetting, error) {
	network := normalizeNetwork(p.Network)
	switch network {
	case "tcp", "ws", "grpc", "xhttp", "httpupgrade", "kcp":
	case "http":
		return nil, fmt.Errorf("HTTP/2 transport (type=http) was removed in Xray 26; use type=xhttp")
	case "quic":
		return nil, fmt.Errorf("QUIC transport (type=quic) was removed in Xray 26; use type=xhttp")
	default:
		return nil, fmt.Errorf("unsupported transport type %q", p.Network)
	}

	security := strings.ToLower(strings.TrimSpace(p.Security))
	switch security {
	case "":
		security = "none"
	case "none", "tls", "reality":
	case "xtls":
		return nil, fmt.Errorf("legacy xtls security was removed; use tls or reality")
	default:
		return nil, fmt.Errorf("unsupported security %q", p.Security)
	}

	stream := &StreamSetting{
		Network:   network,
		Security:  security,
		SocketOpt: defaultSocketOpt(),
	}

	switch network {
	case "ws":
		stream.WsSettings = &WsConfig{
			Path: defaultString(p.Path, "/"),
			Host: firstCSV(p.Host),
		}
	case "grpc":
		serviceName := p.ServiceName
		if serviceName == "" {
			serviceName = p.Path
		}
		authority := p.Authority
		if authority == "" {
			authority = p.Host
		}
		stream.GRPCSettings = &GRPCConfig{
			ServiceName: serviceName,
			Authority:   authority,
			MultiMode:   strings.EqualFold(p.Mode, "multi") || strings.EqualFold(p.Mode, "multimode"),
		}
	case "xhttp":
		extra := p.Extra
		if len(extra) > 0 {
			decoded, err := decodeJSONParam(string(extra))
			if err != nil {
				return nil, fmt.Errorf("xhttp: %w", err)
			}
			extra = decoded
		}
		mode := strings.ToLower(strings.TrimSpace(p.Mode))
		switch mode {
		case "", "auto", "packet-up", "stream-up", "stream-one":
		default:
			return nil, fmt.Errorf("unsupported xhttp mode %q", p.Mode)
		}
		stream.XhttpSettings = &XhttpConfig{
			Mode:  mode,
			Path:  defaultString(p.Path, "/"),
			Host:  firstCSV(p.Host),
			Extra: extra,
		}
	case "httpupgrade":
		stream.HttpUpgradeSettings = &HttpUpgradeConfig{
			Path: defaultString(p.Path, "/"),
			Host: firstCSV(p.Host),
		}
	case "tcp":
		if headerType := strings.ToLower(strings.TrimSpace(p.HeaderType)); headerType != "" && headerType != "none" {
			if headerType != "http" {
				return nil, fmt.Errorf("unsupported tcp headerType %q", p.HeaderType)
			}
			stream.TCPSettings = &TCPConfig{
				Header: &TCPHeader{
					Type: "http",
					Request: &TCPHTTPRequest{
						Version: "1.1",
						Method:  "GET",
						Path:    []string{defaultString(p.Path, "/")},
						Headers: map[string][]string{
							"Host":            {defaultString(firstCSV(p.Host), address)},
							"User-Agent":      {chromeUserAgent},
							"Accept-Encoding": {"gzip, deflate"},
							"Connection":      {"keep-alive"},
							"Pragma":          {"no-cache"},
						},
					},
				},
			}
		}
	case "kcp":
		// Modern Xray uses the default mKCP parameters. Seed/headerType are
		// no longer exposed by the current config builder, so they are
		// intentionally ignored here.
	}

	if len(p.FinalMask) > 0 {
		finalMask, err := decodeJSONParam(string(p.FinalMask))
		if err != nil {
			return nil, fmt.Errorf("finalmask: %w", err)
		}
		stream.FinalMask = finalMask
	}

	switch security {
	case "tls":
		tls := &TlsConfig{
			ServerName:           deriveServerName(p.SNI, p.Host, address),
			AllowInsecure:        p.AllowInsecure,
			Alpn:                 p.Alpn,
			Fingerprint:          defaultString(p.Fingerprint, "chrome"),
			PinnedPeerCertSha256: p.PCS,
			VerifyPeerCertByName: p.VCN,
			EchConfigList:        p.ECH,
		}
		// pcs/vcn are the modern replacement for allowInsecure. When either
		// is present it takes priority and verification stays enabled.
		if tls.PinnedPeerCertSha256 != "" || tls.VerifyPeerCertByName != "" {
			tls.AllowInsecure = false
		}
		stream.TlsSettings = tls
	case "reality":
		if network != "tcp" && network != "xhttp" && network != "grpc" {
			return nil, fmt.Errorf("REALITY only supports tcp, xhttp and grpc transports (got %s)", network)
		}
		if p.PublicKey == "" {
			return nil, fmt.Errorf("REALITY requires a public key (pbk)")
		}
		key, err := decodeBase64(p.PublicKey)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("invalid REALITY public key (pbk): expected 32 bytes of base64")
		}
		// Xray decodes publicKey with RawURLEncoding, so canonicalize padded
		// and standard-base64 inputs before emitting the JSON config.
		publicKey := base64.RawURLEncoding.EncodeToString(key)
		mldsa65Verify := p.Mldsa65Verify
		if mldsa65Verify != "" {
			decoded, err := decodeBase64(mldsa65Verify)
			if err != nil || len(decoded) != 1952 {
				return nil, fmt.Errorf("invalid REALITY mldsa65Verify (pqv): expected 1952 bytes of base64")
			}
			mldsa65Verify = base64.RawURLEncoding.EncodeToString(decoded)
		}
		shortID := strings.TrimSpace(p.ShortID)
		if shortID != "" {
			if len(shortID) > 16 {
				return nil, fmt.Errorf("REALITY shortId is too long (max 16 hex chars)")
			}
			if _, err := hex.DecodeString(shortID); err != nil {
				return nil, fmt.Errorf("invalid REALITY shortId %q: %w", shortID, err)
			}
		}
		spiderX := strings.TrimSpace(p.SpiderX)
		if spiderX != "" && !strings.HasPrefix(spiderX, "/") {
			spiderX = "/" + spiderX
		}
		stream.RealitySettings = &RealityConfig{
			ServerName:    deriveServerName(p.SNI, p.Host, address),
			PublicKey:     publicKey,
			ShortId:       shortID,
			Fingerprint:   defaultString(p.Fingerprint, "chrome"),
			SpiderX:       spiderX,
			Mldsa65Verify: mldsa65Verify,
		}
	}

	return stream, nil
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// appendSalamanderMask adds Xray's Hysteria Salamander obfuscation to a
// finalmask object, preserving any existing TCP/UDP masks.
func appendSalamanderMask(existing json.RawMessage, password string) (json.RawMessage, error) {
	root := map[string]json.RawMessage{}
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &root); err != nil {
			return nil, fmt.Errorf("invalid finalmask JSON: %w", err)
		}
	}

	var udp []json.RawMessage
	if raw, ok := root["udp"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &udp); err != nil {
			return nil, fmt.Errorf("invalid finalmask.udp: %w", err)
		}
	}

	entry, err := json.Marshal(map[string]interface{}{
		"type":     "salamander",
		"settings": map[string]string{"password": password},
	})
	if err != nil {
		return nil, err
	}
	udp = append(udp, entry)
	udpJSON, err := json.Marshal(udp)
	if err != nil {
		return nil, err
	}
	root["udp"] = udpJSON
	return json.Marshal(root)
}
