package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"hellcat/config"
	"hellcat/parser"
	"hellcat/stressor"
)

// version is overwritten at build time:
//
//	go build -ldflags "-X main.version=v3.1.0"
var version = "dev"

const (
	hardProxyLimit       = 100_000
	hardThreadLimit      = 1_000_000
	hardInstanceLimit    = 1_000
	maxLoggedParseErrors = 10
	scannerInitSize      = 64 * 1024
	scannerMaxSize       = 4 * 1024 * 1024
)

func main() {
	rawURL := flag.String("url", "", "Single proxy link (vless/vmess/ss/trojan/hysteria2)")
	listFile := flag.String("list", "", "File with one proxy link per line ('-' reads stdin)")
	maxProxies := flag.Int("max-proxies", 0, "Maximum proxies to load (0 = 100000 hard limit)")
	threadCount := flag.Int("threads", 200, "Total worker goroutines (distributed across instances)")
	duration := flag.Int("duration", 0, "Run duration in seconds (0 = until interrupted)")
	numXray := flag.Int("instances", 20, "Number of Xray processes")
	insane := flag.Bool("insane", false, "Double the worker count and burst size")
	stealth := flag.Bool("stealth", false, "Use low-volume page requests instead of large downloads")
	customTarget := flag.String("target", "", "Custom download URL (overrides built-in targets)")
	fakelogin := flag.Bool("fakelogin", false, "Rotate UUID/password after every 1000 requests")
	cpuTarget := flag.Int("cpu", 0, "CPU usage target % (0 = auto, -1 = disable CPU throttling)")
	maxInFlight := flag.Int("inflight", 0, "Maximum concurrent requests (0 = 10000)")
	legacyInsecure := flag.Bool("legacy-insecure", false, "Emit tlsSettings.allowInsecure (older Xray only)")
	verbose := flag.Bool("verbose", false, "Print Xray process output to stderr")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("hellcat %s\n", version)
		return
	}
	validateFlags(*rawURL, *listFile, *threadCount, *duration, *numXray, *cpuTarget, *maxInFlight, *customTarget)

	if *maxProxies < 0 {
		log.Fatalf("[!] --max-proxies cannot be negative")
	}
	switch {
	case *maxProxies == 0:
		log.Printf("[hellcat] ℹ️ No --max-proxies set. Using default limit: %d", hardProxyLimit)
		*maxProxies = hardProxyLimit
	case *maxProxies > hardProxyLimit:
		log.Printf("[!] Capping --max-proxies from %d to %d.", *maxProxies, hardProxyLimit)
		*maxProxies = hardProxyLimit
	}

	config.CleanupStale(24 * time.Hour)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *rawURL != "" && *listFile != "" {
		log.Println("[!] Both --url and --list were provided. --list is ignored.")
	}

	configs, err := parseConfigs(ctx, *rawURL, *listFile, *maxProxies)
	if err != nil {
		log.Fatalf("[!] %v", err)
	}
	if len(configs) == 0 {
		log.Fatal("[!] No valid proxy links found. Specify --url or --list.")
	}

	logProtocolSummary(configs)

	if insecure := countInsecure(configs); insecure > 0 {
		if *legacyInsecure {
			log.Printf("[hellcat] ⚠️ %d link(s) use insecure TLS. --legacy-insecure is enabled; this only works with older Xray releases.", insecure)
		} else {
			log.Printf("[hellcat] ⚠️ %d link(s) request insecure TLS. Current Xray removed allowInsecure; add pcs/vcn to those links or use --legacy-insecure with an older Xray.", insecure)
		}
	}

	inflight := *maxInFlight
	if inflight <= 0 {
		inflight = 10_000
	}
	warnFileLimit(inflight + *numXray*32 + 512)

	if err := stressor.Run(ctx, configs, stressor.Options{
		Threads:        *threadCount,
		Duration:       *duration,
		Instances:      *numXray,
		Insane:         *insane,
		Stealth:        *stealth,
		CustomTarget:   *customTarget,
		FakeLogin:      *fakelogin,
		CPUTarget:      *cpuTarget,
		MaxInFlight:    inflight,
		LegacyInsecure: *legacyInsecure,
		Verbose:        *verbose,
	}); err != nil {
		log.Fatalf("[!] %v", err)
	}
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "hellcat %s - proxy bandwidth / stress tester\n\n", version)
	fmt.Fprintf(out, "Usage:\n  hellcat --url <link> [flags]\n  hellcat --list <file|-> [flags]\n\nFlags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(out, `
Examples:
  hellcat --url 'vless://uuid@host:443?type=ws&security=tls#node'
  hellcat --list links.txt --threads 400 --instances 40 --duration 300
  cat links.txt | hellcat --list - --stealth --cpu -1
  hellcat --list links.txt --cpu 60 --inflight 20000 --legacy-insecure
`)
}

func validateFlags(rawURL, listFile string, threads, duration, instances, cpu int, inflight int, target string) {
	switch {
	case rawURL == "" && listFile == "":
		log.Fatal("[!] Specify --url or --list. Use --help for details.")
	case threads < 1:
		log.Fatalf("[!] --threads must be at least 1")
	case threads > hardThreadLimit:
		log.Fatalf("[!] --threads cannot exceed %d", hardThreadLimit)
	case instances < 1:
		log.Fatalf("[!] --instances must be at least 1")
	case instances > hardInstanceLimit:
		log.Fatalf("[!] --instances cannot exceed %d", hardInstanceLimit)
	case duration < 0:
		log.Fatalf("[!] --duration cannot be negative")
	case cpu < -1:
		log.Fatalf("[!] --cpu must be 0 (auto), -1 (disabled) or a positive percentage")
	case inflight < 0:
		log.Fatalf("[!] --inflight cannot be negative")
	case target != "":
		u, err := url.Parse(target)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			log.Fatalf("[!] --target must be a valid http(s) URL")
		}
	}
}

func parseConfigs(ctx context.Context, rawURL, listFile string, maxProxies int) ([]*parser.OutboundConfig, error) {
	if rawURL != "" {
		cfg, err := parser.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("parse error: %w", err)
		}
		return []*parser.OutboundConfig{cfg}, nil
	}

	var reader io.Reader
	if listFile == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(listFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %q: %w", listFile, err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Printf("[!] Error closing list file: %v", err)
			}
		}()
		reader = file
	}

	configs := make([]*parser.OutboundConfig, 0, 1024)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, scannerInitSize), scannerMaxSize)

	parseErrors, loggedErrors := 0, 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			log.Println("[hellcat] ⚠️ Proxy loading interrupted by signal.")
			return configs, nil
		}

		raw := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		cfg, err := parser.Parse(raw)
		if err != nil {
			parseErrors++
			if loggedErrors < maxLoggedParseErrors {
				log.Printf("[!] Parse error (%s): %v", truncateRunes(raw, 50), err)
				loggedErrors++
			}
			continue
		}

		configs = append(configs, cfg)
		if len(configs) >= maxProxies {
			log.Printf("[hellcat] ℹ️ Reached --max-proxies limit (%d). Stopping read.", maxProxies)
			break
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[!] Error reading list: %v", err)
	}
	if parseErrors > loggedErrors {
		log.Printf("[hellcat] ⚠️ %d link(s) were skipped because of parse errors", parseErrors)
	}
	return configs, nil
}

func logProtocolSummary(configs []*parser.OutboundConfig) {
	counts := make(map[string]int)
	order := make([]string, 0, 6)
	for _, cfg := range configs {
		if _, ok := counts[cfg.Protocol]; !ok {
			order = append(order, cfg.Protocol)
		}
		counts[cfg.Protocol]++
	}
	parts := make([]string, 0, len(order))
	for _, protocol := range order {
		parts = append(parts, fmt.Sprintf("%s=%d", protocol, counts[protocol]))
	}
	log.Printf("[hellcat] ✅ Loaded %d proxy config(s): %s", len(configs), strings.Join(parts, ", "))
}

func countInsecure(configs []*parser.OutboundConfig) int {
	count := 0
	for _, cfg := range configs {
		if cfg.StreamSetting != nil && cfg.StreamSetting.TlsSettings != nil && cfg.StreamSetting.TlsSettings.AllowInsecure {
			count++
		}
	}
	return count
}

func warnFileLimit(needed int) {
	data, err := os.ReadFile("/proc/self/limits")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[3] == "unlimited" {
			return
		}
		soft, err := strconv.Atoi(fields[3])
		if err != nil {
			return
		}
		if soft < needed {
			log.Printf("[hellcat] ⚠️ RLIMIT_NOFILE soft limit is %d, but about %d open files are recommended. Raise it with `ulimit -n` or systemd LimitNOFILE.", soft, needed)
		}
		return
	}
}

func truncateRunes(s string, maxRunes int) string {
	count := 0
	for i := range s {
		if count >= maxRunes {
			return s[:i] + "..."
		}
		count++
	}
	return s
}
