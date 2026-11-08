// Package parser converts proxy share links (vless://, vmess://, ss://, ...)
// into outbound configurations understood by Xray-core.
package parser

import "encoding/json"

// OutboundConfig is a single Xray outbound plus its transport settings.
// One instance of Xray is started per outbound, exposing a local SOCKS proxy.
type OutboundConfig struct {
	Tag           string         `json:"tag"`
	Protocol      string         `json:"protocol"`
	Mux           MuxConfig      `json:"mux"`
	Settings      interface{}    `json:"settings"`
	StreamSetting *StreamSetting `json:"streamSettings,omitempty"`
}

type MuxConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
}

// StreamSetting mirrors the subset of Xray streamSettings that share links can
// express.
type StreamSetting struct {
	Network             string                  `json:"network"`
	Security            string                  `json:"security"`
	TlsSettings         *TlsConfig              `json:"tlsSettings,omitempty"`
	RealitySettings     *RealityConfig          `json:"realitySettings,omitempty"`
	WsSettings          *WsConfig               `json:"wsSettings,omitempty"`
	GRPCSettings        *GRPCConfig             `json:"grpcSettings,omitempty"`
	XhttpSettings       *XhttpConfig            `json:"xhttpSettings,omitempty"`
	HttpUpgradeSettings *HttpUpgradeConfig      `json:"httpupgradeSettings,omitempty"`
	TCPSettings         *TCPConfig              `json:"tcpSettings,omitempty"`
	HysteriaSettings    *HysteriaStreamSettings `json:"hysteriaSettings,omitempty"`
	FinalMask           json.RawMessage         `json:"finalmask,omitempty"`
	SocketOpt           SocketOpt               `json:"sockopt"`
}

type TlsConfig struct {
	ServerName           string   `json:"serverName,omitempty"`
	AllowInsecure        bool     `json:"allowInsecure,omitempty"`
	Alpn                 []string `json:"alpn,omitempty"`
	Fingerprint          string   `json:"fingerprint,omitempty"`
	PinnedPeerCertSha256 string   `json:"pinnedPeerCertSha256,omitempty"`
	VerifyPeerCertByName string   `json:"verifyPeerCertByName,omitempty"`
	EchConfigList        string   `json:"echConfigList,omitempty"`
}

type RealityConfig struct {
	ServerName    string `json:"serverName,omitempty"`
	PublicKey     string `json:"publicKey"`
	ShortId       string `json:"shortId,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	SpiderX       string `json:"spiderX,omitempty"`
	Mldsa65Verify string `json:"mldsa65Verify,omitempty"`
}

type WsConfig struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type GRPCConfig struct {
	ServiceName string `json:"serviceName,omitempty"`
	Authority   string `json:"authority,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}

type XhttpConfig struct {
	Mode  string          `json:"mode,omitempty"`
	Path  string          `json:"path,omitempty"`
	Host  string          `json:"host,omitempty"`
	Extra json.RawMessage `json:"extra,omitempty"`
}

type HttpUpgradeConfig struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

// TCPConfig carries the legacy HTTP header obfuscation used by some
// `headerType=http` links.
type TCPConfig struct {
	Header *TCPHeader `json:"header,omitempty"`
}

type TCPHeader struct {
	Type    string          `json:"type"`
	Request *TCPHTTPRequest `json:"request,omitempty"`
}

type TCPHTTPRequest struct {
	Version string              `json:"version,omitempty"`
	Method  string              `json:"method,omitempty"`
	Path    []string            `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// HysteriaStreamSettings is Xray's `streamSettings.hysteriaSettings`.
// Xray only implements Hysteria 2, so Version is always 2.
type HysteriaStreamSettings struct {
	Version        int    `json:"version"`
	Auth           string `json:"auth,omitempty"`
	UdpIdleTimeout int    `json:"udpIdleTimeout,omitempty"`
}

// HysteriaClientSettings is Xray's `settings` object for the hysteria
// outbound.
type HysteriaClientSettings struct {
	Version int    `json:"version"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type SocketOpt struct {
	DomainStrategy string         `json:"domainStrategy"`
	HappyEyeballs  *HappyEyeballs `json:"happyEyeballs,omitempty"`
}

type HappyEyeballs struct {
	Interleave       int  `json:"interleave"`
	MaxConcurrentTry int  `json:"maxConcurrentTry"`
	PrioritizeIPv6   bool `json:"prioritizeIPv6"`
	TryDelayMs       int  `json:"tryDelayMs"`
}

type VnextSettings struct {
	Vnext []Vnext `json:"vnext"`
}

type Vnext struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Users   []User `json:"users"`
}

type User struct {
	Id         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
	Level      int    `json:"level"`
}

type VMessSettings struct {
	Vnext []VMessVnext `json:"vnext"`
}

type VMessVnext struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []VMessUser `json:"users"`
}

type VMessUser struct {
	Id       string `json:"id"`
	AlterId  int    `json:"alterId"`
	Security string `json:"security"`
}

// ServerSettings is used by shadowsocks and trojan outbounds. Xray still
// accepts the legacy `servers` array on every supported version.
type ServerSettings struct {
	Servers []ServerEntry `json:"servers"`
}

type ServerEntry struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
}
