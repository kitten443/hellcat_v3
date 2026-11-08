package config

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hellcat/parser"
)

const (
	testUUID = "11111111-1111-1111-1111-111111111111"
	testPBK  = "gFI9xjPPAMzzjhKpdO6IzZ_A2JXaioRE_PVKIKW9bjw"
)

func TestGenerateWithPort(t *testing.T) {
	cfg, err := parser.Parse("vless://" + testUUID + "@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&sni=cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name, cleanup, err := GenerateWithPort(cfg, 1080, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(name) != dir {
		t.Fatalf("config written outside temp dir: %s", name)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	inbounds := raw["inbounds"].([]interface{})
	inbound := inbounds[0].(map[string]interface{})
	if int(inbound["port"].(float64)) != 1080 {
		t.Fatalf("inbound port = %v", inbound["port"])
	}
	outbounds := raw["outbounds"].([]interface{})
	outbound := outbounds[0].(map[string]interface{})
	if outbound["protocol"] != "vless" {
		t.Fatalf("protocol = %v", outbound["protocol"])
	}
	stream := outbound["streamSettings"].(map[string]interface{})
	tlsSettings := stream["tlsSettings"].(map[string]interface{})
	if tlsSettings["serverName"] != "cdn.example.com" {
		t.Fatalf("serverName = %v", tlsSettings["serverName"])
	}
	if _, ok := tlsSettings["allowInsecure"]; ok {
		t.Fatal("modern config must not contain allowInsecure")
	}
}

func TestAllowInsecureCompatibility(t *testing.T) {
	cfg, err := parser.Parse("vless://" + testUUID + "@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&sni=cdn.example.com&allowInsecure=1")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	modern, cleanup, err := GenerateWithPort(cfg, 1081, dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if hasAllowInsecure(t, modern) {
		t.Fatal("allowInsecure must be omitted for current Xray")
	}

	legacy, cleanupLegacy, err := GenerateWithPort(cfg, 1082, dir, Options{LegacyAllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupLegacy()
	if !hasAllowInsecure(t, legacy) {
		t.Fatal("allowInsecure must be emitted in legacy mode")
	}
}

func hasAllowInsecure(t *testing.T, name string) bool {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Outbounds []struct {
			StreamSettings struct {
				TLSSettings map[string]interface{} `json:"tlsSettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	value, ok := raw.Outbounds[0].StreamSettings.TLSSettings["allowInsecure"]
	return ok && value == true
}

func TestGeneratedConfigsValidateWithXray(t *testing.T) {
	xray, err := exec.LookPath("xray")
	if err != nil {
		t.Skip("xray binary not found in PATH")
	}

	links := []string{
		"vless://" + testUUID + "@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&fp=chrome",
		"vless://" + testUUID + "@example.com:443?type=tcp&security=reality&pbk=" + testPBK + "&sni=cdn.example.com&sid=abcd&fp=chrome&flow=xtls-rprx-vision",
		"vless://" + testUUID + "@example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fx&mode=stream-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&sni=cdn.example.com",
		"vless://" + testUUID + "@example.com:443?type=grpc&security=tls&serviceName=svc&authority=cdn.example.com&sni=cdn.example.com",
		"vless://" + testUUID + "@example.com:443?type=grpc&security=reality&pbk=" + testPBK + "&sni=cdn.example.com&sid=abcd&serviceName=svc&authority=cdn.example.com",
		"vless://" + testUUID + "@example.com:443?type=tcp&security=tls&sni=cdn.example.com",
		"vless://" + testUUID + "@127.0.0.1:443?type=tcp&security=none",
		"vless://" + testUUID + "@example.com:443?type=httpupgrade&security=tls&host=cdn.example.com&path=%2Fup&sni=cdn.example.com",
		"vless://" + testUUID + "@127.0.0.1:80?type=tcp&security=none&headerType=http&host=obfs.example.com&path=%2Fdownload",
		"vless://" + testUUID + "@127.0.0.1:443?type=kcp&security=none",
		"vmess://" + "eyJ2IjoiMiIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExIiwibmV0Ijoid3MiLCJob3N0IjoiY2RuLmV4YW1wbGUuY29tIiwicGF0aCI6Ii93cyIsInRscyI6InRscyIsInNuaSI6ImNkbi5leGFtcGxlLmNvbSJ9",
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#node",
		"trojan://password@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Ft&sni=cdn.example.com",
		"trojan://password@example.com:443?security=reality&pbk=" + testPBK + "&sni=cdn.example.com&sid=abcd",
		"trojan://password@example.com:443?type=grpc&security=reality&pbk=" + testPBK + "&sni=cdn.example.com&sid=abcd&serviceName=svc",
		"hysteria2://user:pass@example.com:443?sni=cdn.example.com&insecure=1",
		"hysteria2://user:pass@example.com:443?sni=cdn.example.com&alpn=h3&pcs=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"hysteria2://user:pass@example.com:443?sni=cdn.example.com&obfs=salamander&obfs-password=secret",
	}

	dir := t.TempDir()
	for _, link := range links {
		cfg, err := parser.Parse(link)
		if err != nil {
			t.Fatalf("parse %q: %v", link, err)
		}
		name, cleanup, err := GenerateWithPort(cfg, 11000, dir, Options{})
		if err != nil {
			t.Fatalf("generate %q: %v", link, err)
		}
		output, err := exec.Command(xray, "run", "-test", "-config", name).CombinedOutput()
		cleanup()
		if err != nil {
			t.Fatalf("xray rejected %q:\n%s", link, output)
		}
		if !containsConfigurationOK(output) {
			t.Fatalf("xray did not confirm %q:\n%s", link, output)
		}
	}
}

func containsConfigurationOK(output []byte) bool {
	return strings.Contains(string(output), "Configuration OK")
}

func TestCleanupStaleKeepsFreshDirectories(t *testing.T) {
	dir, err := os.MkdirTemp("", TempDirPrefix)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	CleanupStale(time.Hour)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("fresh temp directory was removed: %v", err)
	}

	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	CleanupStale(time.Hour)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("stale temp directory was not removed: %v", err)
	}
}
