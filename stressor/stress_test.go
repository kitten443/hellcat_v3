package stressor

import (
	"strings"
	"testing"

	"hellcat/parser"
)

func TestFormatSpeed(t *testing.T) {
	cases := map[float64]string{
		512:                    "512 B/s",
		2048:                   "2 KB/s",
		5 * 1024 * 1024:        "5.0 MB/s",
		2 * 1024 * 1024 * 1024: "2.00 GB/s",
	}
	for input, want := range cases {
		if got := formatSpeed(input); got != want {
			t.Errorf("formatSpeed(%v) = %q, want %q", input, got, want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[uint64]string{
		512:                    "512 B",
		2048:                   "2 KiB",
		5 * 1024 * 1024:        "5.0 MiB",
		2 * 1024 * 1024 * 1024: "2.00 GiB",
	}
	for input, want := range cases {
		if got := formatBytes(input); got != want {
			t.Errorf("formatBytes(%v) = %q, want %q", input, got, want)
		}
	}
}

func TestDiscardBody(t *testing.T) {
	payload := strings.Repeat("x", 100_000)
	total, err := discardBody(strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if total != int64(len(payload)) {
		t.Fatalf("total = %d, want %d", total, len(payload))
	}
}

func TestTailBufferKeepsUsefulLines(t *testing.T) {
	buffer := newTailBuffer(1024)
	_, _ = buffer.Write([]byte("Xray 26.10.31\nA unified platform\n"))
	_, _ = buffer.Write([]byte("Failed to start: vless without TLS is prohibited\n"))
	summary := buffer.Summary()
	if !strings.Contains(summary, "Failed to start") {
		t.Fatalf("summary = %q", summary)
	}
}

func TestTailBufferRespectsLimit(t *testing.T) {
	buffer := newTailBuffer(16)
	_, _ = buffer.Write([]byte("0123456789abcdefghij"))
	if got := string(buffer.data); got != "456789abcdefghij" {
		t.Fatalf("buffer = %q, want the last 16 bytes", got)
	}
}

func TestMutateCredentialsDoesNotTouchOriginal(t *testing.T) {
	cfg, err := parser.Parse("vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&security=tls&host=cdn.example.com&path=%2Fws&sni=cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	copy := parser.Clone(cfg)
	mutateCredentials(copy)

	original := cfg.Settings.(parser.VnextSettings)
	changed := copy.Settings.(parser.VnextSettings)
	if original.Vnext[0].Users[0].Id != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("original UUID was mutated: %s", original.Vnext[0].Users[0].Id)
	}
	if changed.Vnext[0].Users[0].Id == original.Vnext[0].Users[0].Id {
		t.Fatal("clone UUID was not rotated")
	}
}

func TestMutateServerPassword(t *testing.T) {
	cfg, err := parser.Parse("ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388")
	if err != nil {
		t.Fatal(err)
	}
	copy := parser.Clone(cfg)
	mutateCredentials(copy)
	original := cfg.Settings.(parser.ServerSettings).Servers[0].Password
	changed := copy.Settings.(parser.ServerSettings).Servers[0].Password
	if original != "secret" {
		t.Fatalf("original password = %q", original)
	}
	if changed == original || len(changed) != 16 {
		t.Fatalf("rotated password = %q", changed)
	}
}
