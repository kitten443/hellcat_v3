package parser

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testUUID   = "11111111-1111-1111-1111-111111111111"
	testPBK    = "gFI9xjPPAMzzjhKpdO6IzZ_A2JXaioRE_PVKIKW9bjw"
	testShort  = "abcd"
	testPinned = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func mustParse(t *testing.T, raw string) *OutboundConfig {
	t.Helper()
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q) failed: %v", raw, err)
	}
	return cfg
}

func TestParseVLESSWebSocketTLS(t *testing.T) {
	cfg := mustParse(t, "vless://"+testUUID+"@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&fp=chrome#node")
	if cfg.Protocol != "vless" {
		t.Fatalf("protocol = %q", cfg.Protocol)
	}
	settings, ok := cfg.Settings.(VnextSettings)
	if !ok || len(settings.Vnext) != 1 {
		t.Fatalf("unexpected settings: %#v", cfg.Settings)
	}
	server := settings.Vnext[0]
	if server.Address != "example.com" || server.Port != 443 {
		t.Fatalf("server = %+v", server)
	}
	if server.Users[0].Id != testUUID || server.Users[0].Encryption != "none" {
		t.Fatalf("user = %+v", server.Users[0])
	}
	stream := cfg.StreamSetting
	if stream.Network != "ws" || stream.Security != "tls" {
		t.Fatalf("stream = %+v", stream)
	}
	if stream.WsSettings.Path != "/ws" || stream.WsSettings.Host != "cdn.example.com" {
		t.Fatalf("ws = %+v", stream.WsSettings)
	}
	if stream.TlsSettings.ServerName != "cdn.example.com" || stream.TlsSettings.Fingerprint != "chrome" {
		t.Fatalf("tls = %+v", stream.TlsSettings)
	}
	if strings.Join(stream.TlsSettings.Alpn, ",") != "h2,http/1.1" {
		t.Fatalf("alpn = %#v", stream.TlsSettings.Alpn)
	}
}

func TestParseVLESSReality(t *testing.T) {
	cfg := mustParse(t, "vless://"+testUUID+"@example.com:443?type=tcp&security=reality&pbk="+testPBK+"&sni=cdn.example.com&sid="+testShort+"&fp=chrome&spx=%2F&flow=xtls-rprx-vision")
	stream := cfg.StreamSetting
	if stream.Security != "reality" || stream.RealitySettings == nil {
		t.Fatalf("stream = %+v", stream)
	}
	if stream.RealitySettings.PublicKey != testPBK || stream.RealitySettings.ShortId != testShort {
		t.Fatalf("reality = %+v", stream.RealitySettings)
	}
	if stream.RealitySettings.ServerName != "cdn.example.com" || stream.RealitySettings.SpiderX != "/" {
		t.Fatalf("reality = %+v", stream.RealitySettings)
	}
	settings := cfg.Settings.(VnextSettings)
	if settings.Vnext[0].Users[0].Flow != "xtls-rprx-vision" {
		t.Fatalf("flow = %q", settings.Vnext[0].Users[0].Flow)
	}
}

func TestParseVLESSXHTTPExtra(t *testing.T) {
	cfg := mustParse(t, "vless://"+testUUID+"@example.com:443?type=xhttp&security=tls&host=cdn.example.com&path=%2Fx&mode=stream-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D&sni=cdn.example.com")
	stream := cfg.StreamSetting
	if stream.XhttpSettings == nil || stream.XhttpSettings.Mode != "stream-up" {
		t.Fatalf("xhttp = %+v", stream.XhttpSettings)
	}
	var extra map[string]string
	if err := json.Unmarshal(stream.XhttpSettings.Extra, &extra); err != nil {
		t.Fatalf("extra is not valid JSON: %v", err)
	}
	if extra["xPaddingBytes"] != "100-1000" {
		t.Fatalf("extra = %#v", extra)
	}
}

func TestParseVLESSHTTPUpgradeAndTCPHeader(t *testing.T) {
	cfg := mustParse(t, "vless://"+testUUID+"@example.com:443?type=httpupgrade&security=tls&host=cdn.example.com&path=%2Fup&sni=cdn.example.com")
	if cfg.StreamSetting.HttpUpgradeSettings == nil || cfg.StreamSetting.HttpUpgradeSettings.Path != "/up" {
		t.Fatalf("httpupgrade = %+v", cfg.StreamSetting.HttpUpgradeSettings)
	}

	cfg = mustParse(t, "vless://"+testUUID+"@example.com:80?type=tcp&security=none&headerType=http&host=obfs.example.com&path=%2Fdownload")
	if cfg.StreamSetting.TCPSettings == nil || cfg.StreamSetting.TCPSettings.Header == nil {
		t.Fatalf("tcp header missing: %+v", cfg.StreamSetting)
	}
	if cfg.StreamSetting.TCPSettings.Header.Request.Headers["Host"][0] != "obfs.example.com" {
		t.Fatalf("tcp header = %+v", cfg.StreamSetting.TCPSettings.Header)
	}
}

func TestParseVLESSIPv6(t *testing.T) {
	cfg := mustParse(t, "vless://"+testUUID+"@[2001:db8::1]:8443?type=ws&security=tls&host=cdn.example.com&path=%2F&sni=cdn.example.com")
	settings := cfg.Settings.(VnextSettings)
	if settings.Vnext[0].Address != "2001:db8::1" || settings.Vnext[0].Port != 8443 {
		t.Fatalf("server = %+v", settings.Vnext[0])
	}
}

func TestParseVLESSRejectsInvalidFlowAndTransport(t *testing.T) {
	bad := []string{
		"vless://" + testUUID + "@example.com:443?type=ws&security=tls&flow=xtls-rprx-vision",
		"vless://" + testUUID + "@example.com:443?type=http&security=tls",
		"vless://" + testUUID + "@example.com:70000?type=ws",
		"vless://" + testUUID + "@example.com:443?type=ws&security=xtls",
	}
	for _, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestParseVMessJSON(t *testing.T) {
	payload := map[string]interface{}{
		"v":    "2",
		"ps":   "node",
		"add":  "example.com",
		"port": "443",
		"id":   testUUID,
		"aid":  "0",
		"scy":  "auto",
		"net":  "ws",
		"host": "cdn.example.com",
		"path": "/ws",
		"tls":  "tls",
		"sni":  "cdn.example.com",
		"alpn": "h2",
		"fp":   "chrome",
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw := "vmess://" + base64.RawURLEncoding.EncodeToString(encoded)
	cfg := mustParse(t, raw)

	settings, ok := cfg.Settings.(VMessSettings)
	if !ok || len(settings.Vnext) != 1 {
		t.Fatalf("settings = %#v", cfg.Settings)
	}
	if settings.Vnext[0].Port != 443 || settings.Vnext[0].Users[0].Id != testUUID {
		t.Fatalf("server = %+v", settings.Vnext[0])
	}
	if settings.Vnext[0].Users[0].Security != "auto" {
		t.Fatalf("security = %q", settings.Vnext[0].Users[0].Security)
	}
	if cfg.StreamSetting.Network != "ws" || cfg.StreamSetting.TlsSettings.ServerName != "cdn.example.com" {
		t.Fatalf("stream = %+v", cfg.StreamSetting)
	}
}

func TestParseVMessURI(t *testing.T) {
	cfg := mustParse(t, "vmess://"+testUUID+"@example.com:443?encryption=aes-128-gcm&security=tls&type=ws&host=cdn.example.com&path=%2Fws&sni=cdn.example.com")
	settings := cfg.Settings.(VMessSettings)
	if settings.Vnext[0].Users[0].Security != "aes-128-gcm" {
		t.Fatalf("security = %q", settings.Vnext[0].Users[0].Security)
	}
	if cfg.StreamSetting.Network != "ws" || cfg.StreamSetting.Security != "tls" {
		t.Fatalf("stream = %+v", cfg.StreamSetting)
	}
}

func TestParseShadowsocksFormats(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	cases := []string{
		"ss://" + userinfo + "@example.com:8388#node",
		"ss://aes-256-gcm:secret@example.com:8388#node",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret@example.com:8388")) + "#node",
	}
	for _, raw := range cases {
		cfg, err := Parse(raw)
		if err != nil {
			t.Fatalf("Parse(%q): %v", raw, err)
		}
		settings := cfg.Settings.(ServerSettings)
		server := settings.Servers[0]
		if server.Address != "example.com" || server.Port != 8388 {
			t.Fatalf("server = %+v", server)
		}
		if server.Method != "aes-256-gcm" || server.Password != "secret" {
			t.Fatalf("credentials = %+v", server)
		}
	}
}

func TestParseShadowsocksRejectsPluginsAndUnknownCiphers(t *testing.T) {
	userinfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	bad := []string{
		"ss://" + userinfo + "@example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("rc4-md5:secret@example.com:8388")),
	}
	for _, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestParseTrojan(t *testing.T) {
	cfg := mustParse(t, "trojan://p%40ss%3Aword@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Ft&sni=cdn.example.com")
	settings := cfg.Settings.(ServerSettings)
	if settings.Servers[0].Password != "p@ss:word" {
		t.Fatalf("password = %q", settings.Servers[0].Password)
	}
	if cfg.StreamSetting.Network != "ws" || cfg.StreamSetting.TlsSettings.ServerName != "cdn.example.com" {
		t.Fatalf("stream = %+v", cfg.StreamSetting)
	}

	cfg = mustParse(t, "trojan://pass@example.com:443?security=reality&pbk="+testPBK+"&sni=cdn.example.com&sid="+testShort)
	if cfg.StreamSetting.RealitySettings == nil || cfg.StreamSetting.RealitySettings.PublicKey != testPBK {
		t.Fatalf("reality = %+v", cfg.StreamSetting.RealitySettings)
	}
}

func TestParseHysteria2(t *testing.T) {
	cfg := mustParse(t, "hysteria2://user:pass@example.com:443?sni=cdn.example.com&insecure=1&pcs="+testPinned+"&alpn=h3")
	if cfg.Protocol != "hysteria" {
		t.Fatalf("protocol = %q", cfg.Protocol)
	}
	settings := cfg.Settings.(HysteriaClientSettings)
	if settings.Address != "example.com" || settings.Port != 443 || settings.Version != 2 {
		t.Fatalf("settings = %+v", settings)
	}
	stream := cfg.StreamSetting
	if stream.Network != "hysteria" || stream.Security != "tls" {
		t.Fatalf("stream = %+v", stream)
	}
	if stream.HysteriaSettings.Auth != "user:pass" || stream.HysteriaSettings.Version != 2 {
		t.Fatalf("hysteria settings = %+v", stream.HysteriaSettings)
	}
	if stream.TlsSettings.ServerName != "cdn.example.com" || stream.TlsSettings.AllowInsecure {
		t.Fatalf("tls = %+v", stream.TlsSettings)
	}
	if stream.TlsSettings.PinnedPeerCertSha256 != testPinned {
		t.Fatalf("pinned cert = %q", stream.TlsSettings.PinnedPeerCertSha256)
	}
	if strings.Join(stream.TlsSettings.Alpn, ",") != "h3" {
		t.Fatalf("alpn = %#v", stream.TlsSettings.Alpn)
	}

	cfg = mustParse(t, "hy2://password@example.com:8443?insecure=1")
	if !cfg.StreamSetting.TlsSettings.AllowInsecure {
		t.Fatalf("expected allowInsecure to be preserved for legacy handling")
	}

	cfg = mustParse(t, "hy2://password@example.com?mport=8443,9443")
	if port := cfg.Settings.(HysteriaClientSettings).Port; port != 8443 {
		t.Fatalf("mport fallback = %d, want 8443", port)
	}
}

func TestParseHysteria2Salamander(t *testing.T) {
	cfg := mustParse(t, "hysteria2://pass@example.com:443?obfs=salamander&obfs-password=secret")
	if len(cfg.StreamSetting.FinalMask) == 0 {
		t.Fatal("expected finalmask for salamander obfs")
	}
	var mask struct {
		UDP []struct {
			Type     string `json:"type"`
			Settings struct {
				Password string `json:"password"`
			} `json:"settings"`
		} `json:"udp"`
	}
	if err := json.Unmarshal(cfg.StreamSetting.FinalMask, &mask); err != nil {
		t.Fatal(err)
	}
	if len(mask.UDP) != 1 || mask.UDP[0].Type != "salamander" || mask.UDP[0].Settings.Password != "secret" {
		t.Fatalf("finalmask = %s", cfg.StreamSetting.FinalMask)
	}

	if _, err := Parse("hysteria2://pass@example.com:443?obfs=unknown"); err == nil {
		t.Fatal("expected unknown obfs rejection")
	}
	if _, err := Parse("hysteria2://pass@example.com:443?obfs=salamander"); err == nil {
		t.Fatal("expected missing obfs password rejection")
	}
}

func TestParseTuicRejected(t *testing.T) {
	if _, err := Parse("tuic://uuid:pass@example.com:443"); err == nil {
		t.Fatal("expected tuic rejection")
	}
}

func TestParseRejectsUnknownInput(t *testing.T) {
	bad := []string{
		"",
		"http://example.com",
		"vless://",
		"vless://uuid@:443",
		"ss://not-base64",
	}
	for _, raw := range bad {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestCloneIsDeep(t *testing.T) {
	cfg := mustParse(t, "vless://"+testUUID+"@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&sni=cdn.example.com&alpn=h2")
	clone := Clone(cfg)
	cloneSettings := clone.Settings.(VnextSettings)
	cloneSettings.Vnext[0].Users[0].Id = "changed"
	clone.StreamSetting.TlsSettings.Alpn[0] = "changed"
	clone.StreamSetting.WsSettings.Path = "/changed"

	original := cfg.Settings.(VnextSettings)
	if original.Vnext[0].Users[0].Id == "changed" {
		t.Fatal("Clone shared the users slice")
	}
	if cfg.StreamSetting.TlsSettings.Alpn[0] == "changed" {
		t.Fatal("Clone shared the ALPN slice")
	}
	if cfg.StreamSetting.WsSettings.Path == "/changed" {
		t.Fatal("Clone shared stream settings")
	}
}

func TestParseUppercaseScheme(t *testing.T) {
	cfg, err := Parse("VLESS://" + testUUID + "@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&sni=cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "vless" {
		t.Fatalf("protocol = %q", cfg.Protocol)
	}
}

func TestParseVMessFragmentWithAt(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"v":"2","add":"example.com","port":443,"id":"` + testUUID + `","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"cdn.example.com"}`))
	cfg, err := Parse("vmess://" + payload + "#node@example")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "vmess" {
		t.Fatalf("protocol = %q", cfg.Protocol)
	}
}
