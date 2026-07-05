package parser

import (
	"context"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/metacubex/mihomo/adapter"
	clash_outbound "github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/constant"
)

func ParseClashSubscription(_ context.Context, content string) ([]option.Outbound, error) {
	config, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		return nil, E.Cause(err, "parse clash config")
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	var outbounds []option.Outbound
	parserMap := map[constant.AdapterType]clashProxyParser{
		constant.Shadowsocks:  parseShadowsocks,
		constant.ShadowsocksR: parseShadowsocksR,
		constant.Trojan:       parseTrojan,
		constant.Vmess:        parseVmess,
		constant.Vless:        parseVless,
		constant.Socks5:       parseSocks5,
		constant.Http:         parseHttp,
		constant.AnyTLS:       parseAnyTLS,
	}
	for i, proxyMapping := range config.Proxy {
		proxy, err := adapter.ParseProxy(proxyMapping)
		if err != nil {
			return nil, E.Cause(err, "parse proxy ", i)
		}
		var outbound option.Outbound
		outbound.Tag = proxy.Name()
		parser, hasParser := parserMap[proxy.Type()]
		if !hasParser {
			continue
		}
		err = parser(decoder, proxy, proxyMapping, &outbound)
		if err != nil {
			return nil, E.Cause(err, "parse proxy ", i)
		}
		outbounds = append(outbounds, outbound)
	}
	if len(outbounds) > 0 {
		return outbounds, nil
	}
	return nil, E.New("no servers found")
}

type clashProxyParser func(decoder *structure.Decoder, proxy constant.Proxy, proxyMapping map[string]any, outbound *option.Outbound) error

func parseShadowsocks(decoder *structure.Decoder, proxy constant.Proxy, proxyMapping map[string]any, outbound *option.Outbound) error {
	ssOption := &clash_outbound.ShadowSocksOption{}
	err := decoder.Decode(proxyMapping, ssOption)
	if err != nil {
		return err
	}
	outbound.Type = C.TypeShadowsocks
	outbound.Options = &option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     ssOption.Server,
			ServerPort: uint16(ssOption.Port),
		},
		Password:      ssOption.Password,
		Method:        clashShadowsocksCipher(ssOption.Cipher),
		Plugin:        clashPluginName(ssOption.Plugin),
		PluginOptions: clashPluginOptions(ssOption.Plugin, ssOption.PluginOpts),
		Network:       clashNetworks(ssOption.UDP),
	}
	return nil
}

func parseShadowsocksR(decoder *structure.Decoder, proxy constant.Proxy, proxyMapping map[string]any, outbound *option.Outbound) error {
	ssrOption := &clash_outbound.ShadowSocksROption{}
	err := decoder.Decode(proxyMapping, ssrOption)
	if err != nil {
		return err
	}
	outbound.Type = C.TypeShadowsocksR
	outbound.Options = &option.ShadowsocksROutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     ssrOption.Server,
			ServerPort: uint16(ssrOption.Port),
		},
		Password:      ssrOption.Password,
		Method:        clashShadowsocksCipher(ssrOption.Cipher),
		Protocol:      ssrOption.Protocol,
		ProtocolParam: ssrOption.ProtocolParam,
		Obfs:          ssrOption.Obfs,
		ObfsParam:     ssrOption.ObfsParam,
		Network:       clashNetworks(ssrOption.UDP),
	}
	return nil
}

func parseTrojan(decoder *structure.Decoder, proxy constant.Proxy, proxyMapping map[string]any, outbound *option.Outbound) error {
	trojanOption := &clash_outbound.TrojanOption{}
	err := decoder.Decode(proxyMapping, trojanOption)
	if err != nil {
		return err
	}
	outbound.Type = C.TypeTrojan
	outbound.Options = &option.TrojanOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     trojanOption.Server,
			ServerPort: uint16(trojanOption.Port),
		},
		Password: trojanOption.Password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ALPN:       trojanOption.ALPN,
				ServerName: trojanOption.SNI,
				Insecure:   trojanOption.SkipCertVerify,
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     trojanOption.ClientFingerprint != "",
					Fingerprint: trojanOption.ClientFingerprint,
				},
			},
		},
		Transport: clashTransport(trojanOption.Network, clash_outbound.HTTPOptions{}, clash_outbound.HTTP2Options{}, trojanOption.GrpcOpts, trojanOption.WSOpts),
		Network:   clashNetworks(trojanOption.UDP),
	}
	return nil
}

func parseVmess(decoder *structure.Decoder, proxy constant.Proxy, proxyMapping map[string]any, outbound *option.Outbound) error {
	vmessOption := &clash_outbound.VmessOption{}
	err := decoder.Decode(proxyMapping, vmessOption)
	if err != nil {
		return err
	}
	outbound.Type = C.TypeVMess
	outbound.Options = &option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     vmessOption.Server,
			ServerPort: uint16(vmessOption.Port),
		},
		UUID:                vmessOption.UUID,
		Security:            vmessOption.Cipher,
		AlterId:             vmessOption.AlterID,
		AuthenticatedLength: vmessOption.AuthenticatedLength,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    vmessOption.TLS,
				ServerName: vmessOption.ServerName,
				Insecure:   vmessOption.SkipCertVerify,
				ALPN:       vmessOption.ALPN,
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     vmessOption.ClientFingerprint != "",
					Fingerprint: vmessOption.ClientFingerprint,
				},
			},
		},
		PacketEncoding: vmessOption.PacketEncoding,
		Transport:      clashTransport(vmessOption.Network, vmessOption.HTTPOpts, vmessOption.HTTP2Opts, vmessOption.GrpcOpts, vmessOption.WSOpts),
		Network:        clashNetworks(vmessOption.UDP),
	}
	return nil
}

func parseVless(decoder *structure.Decoder, proxy constant.Proxy, proxyMapping map[string]any, outbound *option.Outbound) error {
	vlessOption := &clash_outbound.VlessOption{}
	err := decoder.Decode(proxyMapping, vlessOption)
	if err != nil {
		return err
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    vlessOption.TLS,
		ServerName: vlessOption.ServerName,
		Insecure:   vlessOption.SkipCertVerify,
		ALPN:       vlessOption.ALPN,
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     vlessOption.ClientFingerprint != "",
			Fingerprint: vlessOption.ClientFingerprint,
		},
	}
	if vlessOption.RealityOpts.PublicKey != "" {
		tlsOptions.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: vlessOption.RealityOpts.PublicKey,
			ShortID:   vlessOption.RealityOpts.ShortID,
		}
	}
	outbound.Type = C.TypeVLESS
	clashPacketEncoding := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	outbound.Options = &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     vlessOption.Server,
			ServerPort: uint16(vlessOption.Port),
		},
		UUID:           vlessOption.UUID,
		Flow:           vlessOption.Flow,
		PacketEncoding: clashPacketEncoding(vlessOption.PacketEncoding),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: tlsOptions,
		},
		Transport: clashTransport(vlessOption.Network, vlessOption.HTTPOpts, vlessOption.HTTP2Opts, vlessOption.GrpcOpts, vlessOption.WSOpts),
		Network:   clashNetworks(vlessOption.UDP),
	}
	return nil
}

func parseSocks5(decoder *structure.Decoder, proxy constant.Proxy, proxyMapping map[string]any, outbound *option.Outbound) error {
	socks5Option := &clash_outbound.Socks5Option{}
	err := decoder.Decode(proxyMapping, socks5Option)
	if err != nil {
		return err
	}

	if socks5Option.TLS {
		return E.New("unsupported option: socks5 with TLS")
	}

	outbound.Type = C.TypeSOCKS
	outbound.Options = &option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     socks5Option.Server,
			ServerPort: uint16(socks5Option.Port),
		},
		Username: socks5Option.UserName,
		Password: socks5Option.Password,
		Network:  clashNetworks(socks5Option.UDP),
	}
	return nil
}

func parseHttp(decoder *structure.Decoder, proxy constant.Proxy, proxyMapping map[string]any, outbound *option.Outbound) error {
	httpOption := &clash_outbound.HttpOption{}
	err := decoder.Decode(proxyMapping, httpOption)
	if err != nil {
		return err
	}

	if httpOption.TLS {
		return E.New("unsupported option: http with TLS")
	}

	outbound.Type = C.TypeHTTP
	outbound.Options = &option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     httpOption.Server,
			ServerPort: uint16(httpOption.Port),
		},
		Username: httpOption.UserName,
		Password: httpOption.Password,
	}
	return nil
}

func parseAnyTLS(decoder *structure.Decoder, proxy constant.Proxy, proxyMapping map[string]any, outbound *option.Outbound) error {
	anytlsOption := &clash_outbound.AnyTLSOption{}
	err := decoder.Decode(proxyMapping, anytlsOption)
	if err != nil {
		return err
	}
	outbound.Type = C.TypeAnyTLS
	outbound.Options = &option.AnyTLSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     anytlsOption.Server,
			ServerPort: uint16(anytlsOption.Port),
		},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: anytlsOption.SNI,
				Insecure:   anytlsOption.SkipCertVerify,
				ALPN:       anytlsOption.ALPN,
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     anytlsOption.ClientFingerprint != "",
					Fingerprint: anytlsOption.ClientFingerprint,
				},
			},
		},
		Password:                 anytlsOption.Password,
		IdleSessionCheckInterval: badoption.Duration(time.Duration(anytlsOption.IdleSessionCheckInterval) * time.Second),
		IdleSessionTimeout:       badoption.Duration(time.Duration(anytlsOption.IdleSessionTimeout) * time.Second),
		MinIdleSession:           anytlsOption.MinIdleSession,
	}
	return nil
}

func clashShadowsocksCipher(cipher string) string {
	switch cipher {
	case "dummy":
		return "none"
	}
	return cipher
}

func clashNetworks(udpEnabled bool) option.NetworkList {
	if !udpEnabled {
		return N.NetworkTCP
	}
	return ""
}

func clashPluginName(plugin string) string {
	switch plugin {
	case "obfs":
		return "obfs-local"
	}
	return plugin
}

type shadowsocksPluginOptionsBuilder map[string]any

func (o shadowsocksPluginOptionsBuilder) Build() string {
	var opts []string
	for key, value := range o {
		if value == nil {
			continue
		}
		opts = append(opts, format.ToString(key, "=", value))
	}
	return strings.Join(opts, ";")
}

func clashPluginOptions(plugin string, opts map[string]any) string {
	options := make(shadowsocksPluginOptionsBuilder)
	switch plugin {
	case "obfs":
		options["obfs"] = opts["mode"]
		options["obfs-host"] = opts["host"]
	case "v2ray-plugin":
		options["mode"] = opts["mode"]
		options["tls"] = opts["tls"]
		options["host"] = opts["host"]
		options["path"] = opts["path"]
	}
	return options.Build()
}

func clashTransport(network string, httpOpts clash_outbound.HTTPOptions, h2Opts clash_outbound.HTTP2Options, grpcOpts clash_outbound.GrpcOptions, wsOpts clash_outbound.WSOptions) *option.V2RayTransportOptions {
	switch network {
	case "http":
		var headers map[string]badoption.Listable[string]
		for key, values := range httpOpts.Headers {
			if headers == nil {
				headers = make(map[string]badoption.Listable[string])
			}
			headers[key] = values
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Method:  httpOpts.Method,
				Path:    clashStringList(httpOpts.Path),
				Headers: headers,
			},
		}
	case "h2":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Path: h2Opts.Path,
				Host: h2Opts.Host,
			},
		}
	case "grpc":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: grpcOpts.GrpcServiceName,
			},
		}
	case "ws":
		var headers map[string]badoption.Listable[string]
		for key, value := range wsOpts.Headers {
			if headers == nil {
				headers = make(map[string]badoption.Listable[string])
			}
			headers[key] = []string{value}
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:                wsOpts.Path,
				Headers:             headers,
				MaxEarlyData:        uint32(wsOpts.MaxEarlyData),
				EarlyDataHeaderName: wsOpts.EarlyDataHeaderName,
			},
		}
	default:
		return nil
	}
}

func clashStringList(list []string) string {
	if len(list) > 0 {
		return list[0]
	}
	return ""
}
