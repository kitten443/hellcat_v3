package parser

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseTrojan parses trojan:// links. Trojan always uses a password in the
// userinfo section; a colon inside the password is preserved.
func ParseTrojan(rawURL string) (*OutboundConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Trojan URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "trojan") {
		return nil, fmt.Errorf("not a trojan:// link")
	}
	if u.User == nil {
		return nil, fmt.Errorf("Trojan password is missing")
	}
	password := u.User.Username()
	if extra, ok := u.User.Password(); ok {
		password += ":" + extra
	}
	if password == "" {
		return nil, fmt.Errorf("Trojan password is missing")
	}
	host := u.Hostname()
	if err := validateHost(host); err != nil {
		return nil, fmt.Errorf("Trojan: %w", err)
	}
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return nil, fmt.Errorf("Trojan: %w", err)
	}

	q := u.Query()
	params := streamParamsFromQuery(q)
	// Trojan defaults to TLS unless the link explicitly asks for something
	// else (reality/none).
	if params.Security == "" {
		params.Security = "tls"
	}
	stream, err := buildStreamSettings(params, host)
	if err != nil {
		return nil, fmt.Errorf("Trojan: %w", err)
	}

	settings := ServerSettings{
		Servers: []ServerEntry{{
			Address:  host,
			Port:     port,
			Password: password,
		}},
	}
	return newOutbound("trojan", settings, stream), nil
}
