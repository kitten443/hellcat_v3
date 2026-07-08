// [hellcat]
package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"hellcat/parser"
)

type LogConfig struct {
	LogLevel string `json:"loglevel"`
}

type XrayConfig struct {
	Log       *LogConfig    `json:"log,omitempty"`
	Inbounds  []interface{} `json:"inbounds"`
	Outbounds []interface{} `json:"outbounds"`
}

func Generate(cfg *parser.VLESSConfig) string {
	return GenerateWithPort(cfg, 10808)
}

func GenerateWithPort(cfg *parser.VLESSConfig, port int) string {
	stream := map[string]interface{}{
		"network":  cfg.Network,
		"security": cfg.Security,
	}

	// Transport settings
	switch cfg.Network {
	case "ws":
		wsSettings := map[string]interface{}{
			"path": cfg.Path,
		}
		if cfg.HostHeader != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": cfg.HostHeader,
			}
		}
		stream["wsSettings"] = wsSettings
	case "grpc":
		grpcSettings := map[string]interface{}{
			"serviceName": cfg.ServiceName,
		}
		if cfg.Mode != "" {
			grpcSettings["mode"] = cfg.Mode
		}
		if cfg.Authority != "" {
			grpcSettings["authority"] = cfg.Authority
		}
		stream["grpcSettings"] = grpcSettings
	case "xhttp", "splithttp":
		xhttpSettings := map[string]interface{}{
			"path": cfg.Path,
		}
		if cfg.HostHeader != "" {
			xhttpSettings["host"] = cfg.HostHeader
		}
		if cfg.Mode != "" {
			xhttpSettings["mode"] = cfg.Mode
		}
		stream["xhttpSettings"] = xhttpSettings
	}

	// TLS / Reality
	if cfg.Security == "reality" {
		stream["realitySettings"] = map[string]interface{}{
			"serverName":  cfg.SNI,
			"publicKey":   cfg.PublicKey,
			"shortId":     cfg.ShortID,
			"fingerprint": cfg.Fingerprint,
		}
	} else if cfg.Security == "tls" {
		stream["tlsSettings"] = map[string]interface{}{
			"serverName":    cfg.SNI,
			"allowInsecure": true,
		}
	}

	xrayConf := XrayConfig{
		Log: &LogConfig{LogLevel: "none"}, // отключаем все логи xray
		Inbounds: []interface{}{
			map[string]interface{}{
				"port":     port,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
				},
			},
		},
		Outbounds: []interface{}{
			map[string]interface{}{
				"protocol": "vless",
				"tag":      "vless-out",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": cfg.Host,
							"port":    toInt(cfg.Port),
							"users": []interface{}{
								map[string]interface{}{
									"id":         cfg.ID,
									"encryption": "none",
									"flow":       cfg.Flow,
								},
							},
						},
					},
				},
				"streamSettings": stream,
			},
		},
	}

	fileName := fmt.Sprintf("config_%d_%s.json", port, time.Now().Format("150405"))
	f, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("[hellcat] Error writing config file: %v", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(xrayConf); err != nil {
		log.Fatalf("[hellcat] Error encoding config JSON: %v", err)
	}

	return fileName
}

func toInt(s string) int {
	var i int
	fmt.Sscanf(s, "%d", &i)
	return i
}
