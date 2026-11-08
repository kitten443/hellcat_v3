package stressor

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"hellcat/config"
	"hellcat/parser"
)

const (
	defaultBurstSize   = 3
	insaneBurstSize    = 6
	defaultCPULimit    = 70
	insaneCPULimit     = 85
	workerBaseSleep    = 50 * time.Millisecond
	workerInsaneSleep  = 20 * time.Millisecond
	workerJitter       = 50 * time.Millisecond
	httpTimeout        = 40 * time.Second
	stealthTimeout     = 20 * time.Second
	errorSleepBase     = 200 * time.Millisecond
	errorSleepJitter   = 800 * time.Millisecond
	statsInterval      = 3 * time.Second
	cpuMonitorInterval = 1 * time.Second
	maxThrottleMs      = 5000
	shutdownTimeout    = 5 * time.Second
	workerDrainTimeout = 15 * time.Second
	defaultMaxInFlight = 10_000
	hardMaxInFlight    = 100_000
	discardBufferSize  = 16 * 1024
)

var (
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	}

	defaultPayloads = []string{
		"https://speed.cloudflare.com/__down?bytes=10737418240",
		"https://speed.cloudflare.com/__down?bytes=50000000000",
		"http://speedtest.tele2.net/10GB.zip",
		"http://proof.ovh.net/files/10Gb.dat",
		"https://proof.ovh.net/files/10Gb.dat",
		"http://bouygues.iperf.fr/10G.iso",
		"https://speed.hetzner.de/1GB.bin",
	}

	defaultStealthURLs = []string{
		"https://www.google.com/",
		"https://www.youtube.com/",
		"https://www.reddit.com/r/popular/.json?limit=100",
		"https://www.amazon.com/",
		"https://www.microsoft.com/en-us/windows",
		"https://www.github.com/",
		"https://en.wikipedia.org/wiki/Main_Page",
		"https://upload.wikimedia.org/wikipedia/commons/4/47/PNG_transparency_demonstration_1.png",
		"https://github.com/ArtalkJS/Artalk/releases/download/v2.8.2/artalk_v2.8.2_linux_amd64.tar.gz",
		"https://www.facebook.com/",
		"https://twitter.com/",
		"https://www.instagram.com/",
		"https://www.linkedin.com/",
		"https://www.tiktok.com/",
		"https://t.me/",
		"https://discord.com/",
		"https://www.bbc.com/",
		"https://edition.cnn.com/",
		"https://www.nytimes.com/",
		"https://www.theguardian.com/",
		"https://www.wsj.com/",
		"https://stackoverflow.com/",
		"https://hub.docker.com/",
		"https://www.npmjs.com/",
		"https://pkg.go.dev/",
		"https://dev.to/",
		"https://news.ycombinator.com/",
		"https://www.dropbox.com/",
		"https://drive.google.com/",
		"https://www.icloud.com/",
		"https://imgur.com/",
		"https://flickr.com/",
		"https://www.netflix.com/",
		"https://www.spotify.com/",
		"https://www.twitch.tv/",
		"https://www.imdb.com/",
		"https://www.khanacademy.org/",
		"https://www.coursera.org/",
		"https://www.udemy.com/",
		"https://www.wolframalpha.com/",
		"https://www.ebay.com/",
		"https://www.aliexpress.com/",
		"https://www.walmart.com/",
		"https://www.target.com/",
		"https://weather.com/",
		"https://www.accuweather.com/",
		"https://www.google.com/maps",
		"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css",
		"https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap",
		"https://cdn.pixabay.com/photo/2023/01/01/12/34/sample-768x512.jpg",
		"https://upload.wikimedia.org/wikipedia/commons/a/a5/Example.jpg",
		"https://jsonplaceholder.typicode.com/posts/1",
		"https://api.github.com/repos/golang/go",
		"https://api.weather.gov/points/39.7456,-97.0892",
		"https://wordpress.org/",
		"https://medium.com/",
		"https://habr.com/ru/all/",
		"https://store.steampowered.com/",
		"https://www.epicgames.com/",
	}

	discardPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, discardBufferSize)
			return &buf
		},
	}
)

// tailBuffer keeps the last few kilobytes of Xray output so startup errors are
// visible in hellcat's own log without flooding it.
type tailBuffer struct {
	mu    sync.Mutex
	data  []byte
	limit int
}

func newTailBuffer(limit int) *tailBuffer {
	return &tailBuffer{limit: limit}
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	if len(b.data) > b.limit {
		b.data = append([]byte(nil), b.data[len(b.data)-b.limit:]...)
	}
	return len(p), nil
}

func (b *tailBuffer) Summary() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	text := strings.TrimSpace(string(b.data))
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	interesting := make([]string, 0, 3)
	for _, line := range lines {
		if strings.Contains(line, "Failed") || strings.Contains(line, "failed") ||
			strings.Contains(line, "error") || strings.Contains(line, "Error") {
			interesting = append(interesting, line)
		}
	}
	if len(interesting) > 3 {
		interesting = interesting[len(interesting)-3:]
	}
	if len(interesting) == 0 {
		if len(lines) > 3 {
			lines = lines[len(lines)-3:]
		}
		interesting = lines
	}
	return strings.Join(interesting, " | ")
}

// Options controls one stress run.
type Options struct {
	Threads        int
	Duration       int
	Instances      int
	Insane         bool
	Stealth        bool
	CustomTarget   string
	FakeLogin      bool
	CPUTarget      int
	MaxInFlight    int
	LegacyInsecure bool
	Verbose        bool
}

type XrayInstance struct {
	Cmd      *exec.Cmd
	Cfg      *parser.OutboundConfig
	ConfPath string
	cleanup  func()
	done     chan struct{}
	mu       sync.Mutex
	proxyURL atomic.Value
	ops      uint64
	rotating int32
	port     atomic.Int32
}

func (i *XrayInstance) Port() int {
	return int(i.port.Load())
}

type Stressor struct {
	cfgs           []*parser.OutboundConfig
	threads        int
	duration       int
	numXray        int
	insaneMode     bool
	stealthMode    bool
	customURL      string
	fakeLogin      bool
	cpuTarget      int
	maxInFlight    int
	legacyInsecure bool
	verbose        bool

	instances   []*XrayInstance
	clients     []*http.Client
	payloadURLs []string
	stealthURLs []string

	requests      uint64
	errors        uint64
	bytesDown     uint64
	bytesTotal    uint64
	activeWorkers int32
	burstSize     int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	bgWg   sync.WaitGroup

	rand *mathrand.Rand

	prevCPUIdle  uint64
	prevCPUTotal uint64
	hasProcStat  int32
	cpuUsage     int32
	throttleMs   int32

	sem       chan struct{}
	xrayPath  string
	configDir string
}

func newRand() *mathrand.Rand {
	return mathrand.New(mathrand.NewPCG(mathrand.Uint64(), mathrand.Uint64()))
}

func sleepCtx(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func formatSpeed(bytesPerSec float64) string {
	if bytesPerSec >= 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB/s", bytesPerSec/1024/1024/1024)
	}
	if bytesPerSec >= 1024*1024 {
		return fmt.Sprintf("%.1f MB/s", bytesPerSec/1024/1024)
	}
	if bytesPerSec >= 1024 {
		return fmt.Sprintf("%.0f KB/s", bytesPerSec/1024)
	}
	return fmt.Sprintf("%.0f B/s", bytesPerSec)
}

func formatBytes(total uint64) string {
	value := float64(total)
	switch {
	case value >= 1024*1024*1024*1024:
		return fmt.Sprintf("%.2f TiB", value/1024/1024/1024/1024)
	case value >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GiB", value/1024/1024/1024)
	case value >= 1024*1024:
		return fmt.Sprintf("%.1f MiB", value/1024/1024)
	case value >= 1024:
		return fmt.Sprintf("%.0f KiB", value/1024)
	default:
		return fmt.Sprintf("%d B", total)
	}
}

func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func generatePassword(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			result[i] = chars[0]
			continue
		}
		result[i] = chars[n.Int64()]
	}
	return string(result)
}

func mutateCredentials(cfg *parser.OutboundConfig) {
	switch s := cfg.Settings.(type) {
	case parser.VnextSettings:
		for i := range s.Vnext {
			for j := range s.Vnext[i].Users {
				s.Vnext[i].Users[j].Id = generateUUID()
			}
		}
		cfg.Settings = s
	case parser.VMessSettings:
		for i := range s.Vnext {
			for j := range s.Vnext[i].Users {
				s.Vnext[i].Users[j].Id = generateUUID()
			}
		}
		cfg.Settings = s
	case parser.ServerSettings:
		for i := range s.Servers {
			s.Servers[i].Password = generatePassword(16)
		}
		cfg.Settings = s
	case parser.HysteriaClientSettings:
		if cfg.StreamSetting != nil && cfg.StreamSetting.HysteriaSettings != nil {
			cfg.StreamSetting.HysteriaSettings.Auth = generatePassword(16)
		}
	}
}

func getRandomPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

func waitForProxy(ctx context.Context, port int, done <-chan struct{}, attempts int) bool {
	address := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return false
		}
		select {
		case <-done:
			return false
		default:
		}
		conn, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		if !sleepCtx(ctx, 300*time.Millisecond) {
			return false
		}
	}
	return false
}

func xrayVersion(ctx context.Context, path string) string {
	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(versionCtx, path, "version").Output()
	if err != nil {
		return "xray (version unknown)"
	}
	line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if line == "" {
		return "xray (version unknown)"
	}
	return line
}

// Run starts Xray instances and workers, then blocks until the context is
// cancelled or the configured duration elapses.
func Run(parentCtx context.Context, cfgs []*parser.OutboundConfig, opts Options) error {
	if len(cfgs) == 0 {
		return errors.New("no proxy configs supplied")
	}
	if opts.Instances < 1 {
		return errors.New("instances must be at least 1")
	}
	if opts.MaxInFlight <= 0 {
		opts.MaxInFlight = defaultMaxInFlight
	}
	if opts.MaxInFlight > hardMaxInFlight {
		log.Printf("[hellcat] ⚠️ Capping --inflight from %d to %d", opts.MaxInFlight, hardMaxInFlight)
		opts.MaxInFlight = hardMaxInFlight
	}

	s := &Stressor{
		cfgs:           cfgs,
		threads:        opts.Threads,
		duration:       opts.Duration,
		numXray:        opts.Instances,
		insaneMode:     opts.Insane,
		stealthMode:    opts.Stealth,
		customURL:      opts.CustomTarget,
		fakeLogin:      opts.FakeLogin,
		cpuTarget:      opts.CPUTarget,
		maxInFlight:    opts.MaxInFlight,
		legacyInsecure: opts.LegacyInsecure,
		verbose:        opts.Verbose,
		burstSize:      defaultBurstSize,
		payloadURLs:    defaultPayloads,
		stealthURLs:    defaultStealthURLs,
		rand:           newRand(),
		sem:            make(chan struct{}, opts.MaxInFlight),
	}
	if s.cpuTarget == 0 {
		s.cpuTarget = defaultCPULimit
		if s.insaneMode {
			s.cpuTarget = insaneCPULimit
			s.burstSize = insaneBurstSize
		}
	} else if s.cpuTarget > 100 {
		s.cpuTarget = 100
	}
	if s.customURL != "" {
		s.payloadURLs = []string{s.customURL}
		s.stealthURLs = []string{s.customURL}
	}

	s.ctx, s.cancel = context.WithCancel(parentCtx)
	defer s.cancel()

	xrayPath, err := exec.LookPath("xray")
	if err != nil {
		return fmt.Errorf("'xray' binary not found in PATH: %w", err)
	}
	s.xrayPath = xrayPath
	log.Printf("[hellcat] 🧩 %s", xrayVersion(s.ctx, xrayPath))

	s.configDir, err = config.NewTempDir()
	if err != nil {
		return err
	}
	defer os.RemoveAll(s.configDir)
	defer s.shutdown()

	mode := "HEAVY BANDWIDTH"
	if s.stealthMode {
		mode = "STEALTH BANDWIDTH"
	}
	if s.insaneMode {
		mode = "🔥 INSANE " + mode
	}
	log.Printf("[hellcat] 🌊 %s MODE ENGAGED", mode)
	log.Printf("[hellcat] 📊 %d xray instances | %d threads | burst=%d | max_inflight=%d", s.numXray, s.threads, s.burstSize, s.maxInFlight)
	if s.cpuTarget < 0 {
		log.Printf("[hellcat] 🧠 CPU throttling disabled")
	} else {
		log.Printf("[hellcat] 🧠 CPU target: %d%%", s.cpuTarget)
	}

	if s.duration > 0 {
		log.Printf("[hellcat] ⏱️  Duration: %d sec", s.duration)
		durationTimer := time.AfterFunc(time.Duration(s.duration)*time.Second, func() {
			log.Println("[hellcat] ⏰ Stopping...")
			s.cancel()
		})
		defer durationTimer.Stop()
	}

	if s.cpuTarget >= 0 {
		s.startCPUMonitor()
	}

	started := make([]*XrayInstance, 0, s.numXray)
	for i := 0; i < s.numXray; i++ {
		instance, err := s.startInstance(i)
		if err != nil {
			log.Printf("[hellcat] ❌ xray [%d] start: %v", i, err)
			continue
		}
		started = append(started, instance)
		log.Printf("[hellcat] ✓ xray [%d] PID %d Port %d", i, instance.Cmd.Process.Pid, instance.Port())
		time.Sleep(25 * time.Millisecond)
	}
	if len(started) == 0 {
		return errors.New("no Xray instance could be started")
	}

	log.Println("[hellcat] ⏳ Waiting for SOCKS proxies...")
	ready := make([]*XrayInstance, 0, len(started))
	for _, instance := range started {
		if !waitForProxy(s.ctx, instance.Port(), instance.done, 30) {
			log.Printf("[hellcat] ❌ xray on port %d did not become ready", instance.Port())
			s.stopInstance(instance)
			continue
		}
		ready = append(ready, instance)
	}
	if len(ready) == 0 {
		return errors.New("no SOCKS proxy became ready")
	}
	s.instances = ready
	s.clients = make([]*http.Client, len(ready))
	for i, instance := range ready {
		s.clients[i] = s.newClient(instance)
	}

	workers := s.threads
	if s.insaneMode {
		workers *= 2
	}
	if workers < len(ready) {
		workers = len(ready)
	}
	base, remainder := workers/len(ready), workers%len(ready)
	spawned := 0
	for i, instance := range ready {
		count := base
		if i < remainder {
			count++
		}
		for j := 0; j < count; j++ {
			s.wg.Add(1)
			go s.worker(instance, s.clients[i], newRand())
		}
		spawned += count
	}
	log.Printf("[hellcat] 🚀 Spawning %d workers across %d proxies...", spawned, len(ready))

	s.statsLoop()
	return nil
}

func (s *Stressor) startInstance(index int) (*XrayInstance, error) {
	port, err := getRandomPort()
	if err != nil {
		return nil, fmt.Errorf("port allocation: %w", err)
	}

	cfg := parser.Clone(s.cfgs[index%len(s.cfgs)])
	if cfg == nil {
		return nil, fmt.Errorf("empty proxy config")
	}
	if s.fakeLogin {
		mutateCredentials(cfg)
	}

	confPath, cleanup, err := config.GenerateWithPort(cfg, port, s.configDir, config.Options{
		LegacyAllowInsecure: s.legacyInsecure,
	})
	if err != nil {
		return nil, fmt.Errorf("config generation: %w", err)
	}

	cmd, output := s.newXrayCommand(confPath)
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, err
	}

	done := make(chan struct{})
	instance := &XrayInstance{
		Cmd:      cmd,
		Cfg:      cfg,
		ConfPath: confPath,
		cleanup:  cleanup,
		done:     done,
	}
	instance.port.Store(int32(port))
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
	instance.proxyURL.Store(proxyURL)

	go func() {
		if err := cmd.Wait(); err != nil && s.ctx.Err() == nil {
			logXrayExit(port, err, output)
		}
		close(done)
	}()

	return instance, nil
}

func (s *Stressor) newXrayCommand(confPath string) (*exec.Cmd, *tailBuffer) {
	cmd := exec.Command(s.xrayPath, "run", "-config", confPath)
	setProcAttrs(cmd)
	if s.verbose {
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		return cmd, nil
	}
	output := newTailBuffer(8192)
	cmd.Stdout = output
	cmd.Stderr = output
	return cmd, output
}

func logXrayExit(port int, err error, output *tailBuffer) {
	if output != nil {
		if summary := output.Summary(); summary != "" {
			log.Printf("[hellcat] ⚠️ xray [port %d] exited: %v: %s", port, err, summary)
			return
		}
	}
	log.Printf("[hellcat] ⚠️ xray [port %d] exited: %v", port, err)
}

func (s *Stressor) restartInstance(instance *XrayInstance) {
	if s.ctx.Err() != nil {
		return
	}

	port, err := getRandomPort()
	if err != nil {
		log.Printf("[hellcat] ❌ Failed to get port for restart: %v", err)
		return
	}

	mutateCredentials(instance.Cfg)
	confPath, cleanup, err := config.GenerateWithPort(instance.Cfg, port, s.configDir, config.Options{
		LegacyAllowInsecure: s.legacyInsecure,
	})
	if err != nil {
		log.Printf("[hellcat] ❌ Failed to generate config for restart on port %d: %v", port, err)
		return
	}

	cmd, output := s.newXrayCommand(confPath)
	if err := cmd.Start(); err != nil {
		log.Printf("[hellcat] ❌ Failed to start new xray on port %d: %v", port, err)
		cleanup()
		return
	}

	done := make(chan struct{})
	go func() {
		if err := cmd.Wait(); err != nil && s.ctx.Err() == nil {
			logXrayExit(port, err, output)
		}
		close(done)
	}()

	if !waitForProxy(s.ctx, port, done, 30) {
		log.Printf("[hellcat] ❌ New xray on port %d failed to become ready", port)
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(shutdownTimeout):
		}
		cleanup()
		return
	}

	instance.mu.Lock()
	oldCmd, oldDone, oldCleanup := instance.Cmd, instance.done, instance.cleanup
	instance.Cmd = cmd
	instance.ConfPath = confPath
	instance.cleanup = cleanup
	instance.done = done
	instance.port.Store(int32(port))
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
	instance.proxyURL.Store(proxyURL)
	instance.mu.Unlock()

	stopProcess(oldCmd, oldDone, oldCleanup)
	log.Printf("[hellcat] 🔑 [Port %d] Restarted successfully", port)
}

func (s *Stressor) stopInstance(instance *XrayInstance) {
	if instance == nil {
		return
	}
	instance.mu.Lock()
	cmd, done, cleanup := instance.Cmd, instance.done, instance.cleanup
	instance.mu.Unlock()
	stopProcess(cmd, done, cleanup)
}

func stopProcess(cmd *exec.Cmd, done chan struct{}, cleanup func()) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		if done != nil {
			select {
			case <-done:
			case <-time.After(shutdownTimeout):
				_ = cmd.Process.Kill()
				select {
				case <-done:
				case <-time.After(time.Second):
				}
			}
		}
	}
	if cleanup != nil {
		cleanup()
	}
}

func (s *Stressor) shutdown() {
	log.Println("[hellcat] 🧹 Cleaning up resources...")
	if s.cancel != nil {
		s.cancel()
	}
	s.bgWg.Wait()

	drained := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(workerDrainTimeout):
		log.Println("[hellcat] ⚠️ Workers did not stop in time; terminating Xray processes anyway")
	}

	for _, instance := range s.instances {
		s.stopInstance(instance)
	}
	log.Println("[hellcat] ✅ Finished.")
}

func (s *Stressor) newClient(instance *XrayInstance) *http.Client {
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			if proxyURL := instance.proxyURL.Load(); proxyURL != nil {
				return proxyURL.(*url.URL), nil
			}
			return nil, errors.New("proxy not ready")
		},
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		// Targets are arbitrary public hosts, so certificate validation is
		// intentionally disabled for the inner TLS session.
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     false,
		DisableCompression:    false,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{Transport: transport}
}

func (s *Stressor) acquire() bool {
	select {
	case s.sem <- struct{}{}:
		return true
	case <-s.ctx.Done():
		return false
	}
}

func (s *Stressor) release() {
	<-s.sem
}

func (s *Stressor) applyThrottle(rng *mathrand.Rand) {
	throttle := atomic.LoadInt32(&s.throttleMs)
	if throttle <= 0 {
		return
	}
	jitter := throttle * 3 / 10
	if jitter > 0 {
		throttle += int32(rng.Int64N(int64(jitter))) - jitter/2
		if throttle < 0 {
			throttle = 0
		}
	}
	sleepCtx(s.ctx, time.Duration(throttle)*time.Millisecond)
}

func (s *Stressor) worker(instance *XrayInstance, client *http.Client, rng *mathrand.Rand) {
	defer s.wg.Done()
	atomic.AddInt32(&s.activeWorkers, 1)
	defer atomic.AddInt32(&s.activeWorkers, -1)

	for {
		if s.ctx.Err() != nil {
			return
		}
		s.applyThrottle(rng)

		for i := 0; i < s.burstSize; i++ {
			if s.ctx.Err() != nil {
				return
			}
			var ok bool
			if s.stealthMode {
				ok = s.stealthSingle(instance, client, rng)
			} else {
				ok = s.downloadSingle(instance, client, rng)
			}
			if !ok {
				s.backoff(rng)
			}
		}

		baseSleep := workerBaseSleep
		if s.insaneMode {
			baseSleep = workerInsaneSleep
		}
		if !sleepCtx(s.ctx, baseSleep+time.Duration(rng.Int64N(int64(workerJitter)))) {
			return
		}
	}
}

func (s *Stressor) backoff(rng *mathrand.Rand) {
	sleepCtx(s.ctx, errorSleepBase+time.Duration(rng.Int64N(int64(errorSleepJitter))))
}

func (s *Stressor) downloadSingle(instance *XrayInstance, client *http.Client, rng *mathrand.Rand) bool {
	if len(s.payloadURLs) == 0 {
		return true
	}
	target := s.payloadURLs[rng.IntN(len(s.payloadURLs))]
	if !s.acquire() {
		return true
	}
	ok := s.doRequest(instance, client, rng, target, httpTimeout, true)
	s.release()
	return ok
}

func (s *Stressor) stealthSingle(instance *XrayInstance, client *http.Client, rng *mathrand.Rand) bool {
	if len(s.stealthURLs) == 0 {
		return true
	}
	target := s.stealthURLs[rng.IntN(len(s.stealthURLs))]
	if !s.acquire() {
		return true
	}
	ok := s.doRequest(instance, client, rng, target, stealthTimeout, false)
	s.release()
	return ok
}

func (s *Stressor) doRequest(instance *XrayInstance, client *http.Client, rng *mathrand.Rand, target string, timeout time.Duration, heavy bool) bool {
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		atomic.AddUint64(&instance.ops, 1)
		return false
	}
	req.Header.Set("User-Agent", userAgents[rng.IntN(len(userAgents))])
	if heavy {
		req.Header.Set("Accept-Encoding", "identity")
		req.Close = true
	} else {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		atomic.AddUint64(&instance.ops, 1)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		atomic.AddUint64(&s.errors, 1)
		atomic.AddUint64(&instance.ops, 1)
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return false
	}

	n, err := discardBody(resp.Body)
	atomic.AddUint64(&s.bytesDown, uint64(n))
	atomic.AddUint64(&s.bytesTotal, uint64(n))
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
	} else {
		atomic.AddUint64(&s.requests, 1)
	}
	atomic.AddUint64(&instance.ops, 1)
	return err == nil
}

func discardBody(reader io.Reader) (int64, error) {
	bufferPtr := discardPool.Get().(*[]byte)
	defer discardPool.Put(bufferPtr)
	buffer := *bufferPtr

	var total int64
	for {
		n, err := reader.Read(buffer)
		total += int64(n)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

func (s *Stressor) statsLoop() {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	lastTick := time.Now()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			elapsed := now.Sub(lastTick).Seconds()
			lastTick = now
			if elapsed <= 0 {
				elapsed = statsInterval.Seconds()
			}

			success := atomic.LoadUint64(&s.requests)
			failures := atomic.LoadUint64(&s.errors)
			bytes := atomic.SwapUint64(&s.bytesDown, 0)
			total := atomic.LoadUint64(&s.bytesTotal)
			speed := formatSpeed(float64(bytes) / elapsed)

			log.Printf("[hellcat] 🌊 %s | total %s | req %d | err %d | workers %d | inflight %d/%d | cpu %d%% | throttle %dms",
				speed, formatBytes(total), success, failures,
				atomic.LoadInt32(&s.activeWorkers), len(s.sem), s.maxInFlight,
				atomic.LoadInt32(&s.cpuUsage), atomic.LoadInt32(&s.throttleMs))

			if s.fakeLogin {
				s.rotateInstances()
			}
		}
	}
}

func (s *Stressor) rotateInstances() {
	for _, instance := range s.instances {
		if atomic.LoadUint64(&instance.ops) < 1000 {
			continue
		}
		if !atomic.CompareAndSwapInt32(&instance.rotating, 0, 1) {
			continue
		}
		atomic.StoreUint64(&instance.ops, 0)
		log.Printf("[hellcat] 🔑 Instance on port %d crossed 1000 ops! Rotating...", instance.Port())
		s.bgWg.Add(1)
		go func(target *XrayInstance) {
			defer s.bgWg.Done()
			s.restartInstance(target)
			atomic.StoreInt32(&target.rotating, 0)
		}(instance)
	}
}

func readCPUUsageLinux() (idle uint64, total uint64, err error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return 0, 0, fmt.Errorf("empty /proc/stat")
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("invalid /proc/stat format")
	}

	for i := 1; i < len(fields); i++ {
		value, _ := strconv.ParseUint(fields[i], 10, 64)
		total += value
		if i == 4 {
			idle = value
		}
	}
	return idle, total, nil
}

func (s *Stressor) startCPUMonitor() {
	prevIdle, prevTotal, err := readCPUUsageLinux()
	if err == nil {
		s.prevCPUIdle = prevIdle
		s.prevCPUTotal = prevTotal
		atomic.StoreInt32(&s.hasProcStat, 1)
	} else {
		log.Printf("[hellcat] ⚠️ /proc/stat unavailable, using goroutine-based CPU estimation")
		atomic.StoreInt32(&s.hasProcStat, 0)
	}

	go func() {
		ticker := time.NewTicker(cpuMonitorInterval)
		defer ticker.Stop()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				var usage int32
				idle, total, err := readCPUUsageLinux()
				if err == nil {
					if atomic.LoadInt32(&s.hasProcStat) == 1 {
						if total > s.prevCPUTotal && idle >= s.prevCPUIdle {
							totalDelta := total - s.prevCPUTotal
							idleDelta := idle - s.prevCPUIdle
							if totalDelta > 0 && idleDelta <= totalDelta {
								usage = int32(((totalDelta - idleDelta) * 100) / totalDelta)
							}
						}
					} else {
						atomic.StoreInt32(&s.hasProcStat, 1)
					}
					s.prevCPUIdle = idle
					s.prevCPUTotal = total
				} else {
					atomic.StoreInt32(&s.hasProcStat, 0)
				}

				if atomic.LoadInt32(&s.hasProcStat) == 0 {
					goroutines := runtime.NumGoroutine()
					usage = 50
					switch {
					case goroutines > 2000:
						usage = 95
					case goroutines > 1000:
						usage = 80
					case goroutines > 500:
						usage = 65
					}
				}
				atomic.StoreInt32(&s.cpuUsage, usage)

				target := int32(s.cpuTarget)
				current := atomic.LoadInt32(&s.throttleMs)
				diff := usage - target
				var next int32
				switch {
				case diff > 20:
					next = current + 100
				case diff > 10:
					next = current + 50
				case diff > 0:
					next = current + 20
				case diff > -10:
					next = current - 10
				case diff > -20:
					next = current - 30
				default:
					next = current - 50
				}
				if next < 0 {
					next = 0
				}
				if next > maxThrottleMs {
					next = maxThrottleMs
				}
				atomic.StoreInt32(&s.throttleMs, next)
			}
		}
	}()
}
