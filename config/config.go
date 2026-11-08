// Package config generates temporary Xray-core configuration files.
package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hellcat/parser"
)

// TempDirPrefix is used for per-run temporary directories. Keeping every
// generated config in one directory makes cleanup deterministic and avoids
// scattering files in the current working directory.
const TempDirPrefix = "hellcat-"

// LegacyTempFilePrefix matches files created by older versions of hellcat. They
// are removed on startup when they are old enough to be stale.
const LegacyTempFilePrefix = "hellcat_tmp_"

type Options struct {
	// LegacyAllowInsecure emits tlsSettings.allowInsecure for older Xray
	// versions that still accept it. Current Xray releases reject the option,
	// so it is off by default.
	LegacyAllowInsecure bool
}

type XrayConfig struct {
	Log       *LogConfig     `json:"log,omitempty"`
	Inbounds  []XrayInbound  `json:"inbounds"`
	Outbounds []XrayOutbound `json:"outbounds"`
}

type LogConfig struct {
	LogLevel string `json:"loglevel"`
}

type XrayInbound struct {
	Port     int             `json:"port"`
	Listen   string          `json:"listen"`
	Protocol string          `json:"protocol"`
	Settings InboundSettings `json:"settings"`
}

type InboundSettings struct {
	Auth string `json:"auth"`
}

type XrayOutbound struct {
	Protocol       string          `json:"protocol"`
	Tag            string          `json:"tag,omitempty"`
	Settings       interface{}     `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Mux            *MuxConfig      `json:"mux,omitempty"`
}

type StreamSettings struct {
	Network             string                         `json:"network,omitempty"`
	Security            string                         `json:"security,omitempty"`
	TLSSettings         *parser.TlsConfig              `json:"tlsSettings,omitempty"`
	RealitySettings     *parser.RealityConfig          `json:"realitySettings,omitempty"`
	WSSettings          *parser.WsConfig               `json:"wsSettings,omitempty"`
	GRPCSettings        *parser.GRPCConfig             `json:"grpcSettings,omitempty"`
	XHTTPSettings       *parser.XhttpConfig            `json:"xhttpSettings,omitempty"`
	HTTPUpgradeSettings *parser.HttpUpgradeConfig      `json:"httpupgradeSettings,omitempty"`
	TCPSettings         *parser.TCPConfig              `json:"tcpSettings,omitempty"`
	HysteriaSettings    *parser.HysteriaStreamSettings `json:"hysteriaSettings,omitempty"`
	FinalMask           json.RawMessage                `json:"finalmask,omitempty"`
	SocketOpt           parser.SocketOpt               `json:"sockopt"`
}

type MuxConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
}

// NewTempDir creates the per-run directory that holds generated configs.
func NewTempDir() (string, error) {
	dir, err := os.MkdirTemp("", TempDirPrefix)
	if err != nil {
		return "", fmt.Errorf("create temporary config directory: %w", err)
	}
	return dir, nil
}

// CleanupStale removes temporary configs left behind by crashed runs. Entries
// younger than maxAge are left alone so a concurrently running hellcat process
// is never disturbed.
func CleanupStale(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	if entries, err := os.ReadDir(os.TempDir()); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), TempDirPrefix) {
				continue
			}
			info, err := entry.Info()
			if err != nil || info.ModTime().After(cutoff) {
				continue
			}
			if err := os.RemoveAll(filepath.Join(os.TempDir(), entry.Name())); err == nil {
				removed++
			}
		}
	}

	// Legacy versions wrote hellcat_tmp_*.json into the working directory.
	if matches, err := filepath.Glob(LegacyTempFilePrefix + "*"); err == nil {
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil || info.ModTime().After(cutoff) {
				continue
			}
			if err := os.Remove(match); err == nil {
				removed++
			}
		}
	}

	if removed > 0 {
		log.Printf("[hellcat] 🧹 Removed %d stale temporary config file(s)", removed)
	}
}

// GenerateWithPort writes one Xray config exposing a SOCKS5 inbound on
// 127.0.0.1:port. The returned cleanup function removes the file and is safe to
// call more than once.
func GenerateWithPort(cfg *parser.OutboundConfig, port int, dir string, opts Options) (string, func(), error) {
	if cfg == nil {
		return "", nil, fmt.Errorf("nil outbound config")
	}
	if cfg.Protocol == "" {
		return "", nil, fmt.Errorf("empty outbound protocol")
	}
	if port < 1 || port > 65535 {
		return "", nil, fmt.Errorf("invalid SOCKS port %d", port)
	}
	if dir == "" {
		dir = os.TempDir()
	}

	outbound := XrayOutbound{
		Protocol:       cfg.Protocol,
		Tag:            cfg.Tag,
		Settings:       cfg.Settings,
		StreamSettings: toStreamSettings(cfg.StreamSetting, opts),
	}
	if cfg.Mux.Enabled {
		outbound.Mux = &MuxConfig{Enabled: true, Concurrency: cfg.Mux.Concurrency}
	}

	xrayConf := XrayConfig{
		Log: &LogConfig{LogLevel: "none"},
		Inbounds: []XrayInbound{{
			Port:     port,
			Listen:   "127.0.0.1",
			Protocol: "socks",
			Settings: InboundSettings{Auth: "noauth"},
		}},
		Outbounds: []XrayOutbound{outbound},
	}

	file, err := os.CreateTemp(dir, "xray-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("create temp config: %w", err)
	}
	name := file.Name()
	cleanup := func() {
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			log.Printf("[!] Failed to remove temp config %s: %v", name, err)
		}
	}

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(xrayConf); err != nil {
		_ = file.Close()
		cleanup()
		return "", nil, fmt.Errorf("encode config: %w", err)
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close config: %w", err)
	}
	return name, cleanup, nil
}

func toStreamSettings(stream *parser.StreamSetting, opts Options) *StreamSettings {
	if stream == nil {
		return nil
	}
	out := &StreamSettings{
		Network:             stream.Network,
		Security:            stream.Security,
		RealitySettings:     stream.RealitySettings,
		WSSettings:          stream.WsSettings,
		GRPCSettings:        stream.GRPCSettings,
		XHTTPSettings:       stream.XhttpSettings,
		HTTPUpgradeSettings: stream.HttpUpgradeSettings,
		TCPSettings:         stream.TCPSettings,
		HysteriaSettings:    stream.HysteriaSettings,
		FinalMask:           stream.FinalMask,
		SocketOpt:           stream.SocketOpt,
	}
	if stream.TlsSettings != nil {
		tls := *stream.TlsSettings
		// pcs/vcn are the supported way to skip CA verification in current
		// Xray. Never combine them with the removed allowInsecure option.
		if tls.PinnedPeerCertSha256 != "" || tls.VerifyPeerCertByName != "" {
			tls.AllowInsecure = false
		}
		if !opts.LegacyAllowInsecure {
			tls.AllowInsecure = false
		}
		out.TLSSettings = &tls
	}
	return out
}
