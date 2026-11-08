package parser

// Clone returns a deep copy of an outbound configuration. The stress runner
// uses it before mutating credentials so that fake-login instances never share
// slices with each other.
func Clone(cfg *OutboundConfig) *OutboundConfig {
	if cfg == nil {
		return nil
	}
	out := *cfg
	out.Settings = cloneSettings(cfg.Settings)
	out.StreamSetting = cloneStream(cfg.StreamSetting)
	return &out
}

func cloneSettings(settings interface{}) interface{} {
	switch s := settings.(type) {
	case VnextSettings:
		cp := s
		cp.Vnext = make([]Vnext, len(s.Vnext))
		for i, v := range s.Vnext {
			cp.Vnext[i] = v
			cp.Vnext[i].Users = append([]User(nil), v.Users...)
		}
		return cp
	case VMessSettings:
		cp := s
		cp.Vnext = make([]VMessVnext, len(s.Vnext))
		for i, v := range s.Vnext {
			cp.Vnext[i] = v
			cp.Vnext[i].Users = append([]VMessUser(nil), v.Users...)
		}
		return cp
	case ServerSettings:
		cp := s
		cp.Servers = append([]ServerEntry(nil), s.Servers...)
		return cp
	default:
		return settings
	}
}

func cloneStream(stream *StreamSetting) *StreamSetting {
	if stream == nil {
		return nil
	}
	cp := *stream
	if stream.TlsSettings != nil {
		tls := *stream.TlsSettings
		tls.Alpn = append([]string(nil), stream.TlsSettings.Alpn...)
		cp.TlsSettings = &tls
	}
	if stream.RealitySettings != nil {
		reality := *stream.RealitySettings
		cp.RealitySettings = &reality
	}
	if stream.WsSettings != nil {
		ws := *stream.WsSettings
		cp.WsSettings = &ws
	}
	if stream.GRPCSettings != nil {
		grpc := *stream.GRPCSettings
		cp.GRPCSettings = &grpc
	}
	if stream.XhttpSettings != nil {
		xhttp := *stream.XhttpSettings
		xhttp.Extra = append([]byte(nil), stream.XhttpSettings.Extra...)
		cp.XhttpSettings = &xhttp
	}
	if stream.HttpUpgradeSettings != nil {
		upgrade := *stream.HttpUpgradeSettings
		cp.HttpUpgradeSettings = &upgrade
	}
	if stream.TCPSettings != nil {
		tcp := *stream.TCPSettings
		if stream.TCPSettings.Header != nil {
			header := *stream.TCPSettings.Header
			if stream.TCPSettings.Header.Request != nil {
				request := *stream.TCPSettings.Header.Request
				request.Path = append([]string(nil), request.Path...)
				if request.Headers != nil {
					request.Headers = make(map[string][]string, len(stream.TCPSettings.Header.Request.Headers))
					for key, values := range stream.TCPSettings.Header.Request.Headers {
						request.Headers[key] = append([]string(nil), values...)
					}
				}
				header.Request = &request
			}
			tcp.Header = &header
		}
		cp.TCPSettings = &tcp
	}
	if stream.HysteriaSettings != nil {
		hysteria := *stream.HysteriaSettings
		cp.HysteriaSettings = &hysteria
	}
	cp.FinalMask = append([]byte(nil), stream.FinalMask...)
	if stream.SocketOpt.HappyEyeballs != nil {
		happy := *stream.SocketOpt.HappyEyeballs
		cp.SocketOpt.HappyEyeballs = &happy
	}
	return &cp
}
