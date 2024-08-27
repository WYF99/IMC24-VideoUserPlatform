package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/quic-go/quic-go"
)

type TransportInfo struct {
	packetSize                                 int
	ttl                                        int
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	windowSize                                 int
	options                                    []layers.TCPOption
	layer                                      layers.TCP
}

type ContextInfo struct {
	serverAddress     ServerAddress
	transportProtocol uint8
	localPort         uint16
	transportInfo     TransportInfo
	chlo              HandshakeInfo
}

// ExtractContextAttributes extracts only context attributes from pcap files.
// It examines video servers based on the SNI field.
func ExtractContextAttributes(filePath string, service string, device string, application string, outPath string) {
	fmt.Println("========== Processing file: " + filePath + " ==========")
	if device == "" || application == "" || application == ".." {
		return
	}

	// create parser to decode layer data
	var (
		// Will reuse these for each packet
		ethLayer layers.Ethernet
		ip4Layer layers.IPv4
		ip6Layer layers.IPv6
		tcpLayer layers.TCP
		udpLayer layers.UDP
		tlsLayer layers.TLS
	)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ip4Layer,
		&ip6Layer,
		&tcpLayer,
		&udpLayer,
		&tlsLayer,
	)

	var contexts []ContextInfo
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		panic("unable to open pcap")
	}
	//handle.SetBPFFilter("src port 443 or dst port 443")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true
	//packetSource.DecodeStreamsAsDatagrams = true

	for packet := range packetSource.Packets() {
		// only capture info from CHLO packets
		var contextInfo ContextInfo
		var tcpInfo TransportInfo
		var payload []byte
		if packet.ApplicationLayer() != nil {
			payload = packet.ApplicationLayer().LayerContents()
		}
		// layer processing
		var foundLayerTypes []gopacket.LayerType
		_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		for _, layerType := range foundLayerTypes {
			switch layerType {
			case layers.LayerTypeIPv4:
				contextInfo.serverAddress.Addr = ip4Layer.DstIP.String()
			case layers.LayerTypeIPv6:
				contextInfo.serverAddress.Addr = ip6Layer.DstIP.String()
			case layers.LayerTypeTCP:
				contextInfo.transportProtocol = PROTOCOL_TCP
				contextInfo.localPort = uint16(tcpLayer.SrcPort)
				tcpInfo.packetSize = packet.Metadata().CaptureLength
				tcpInfo.ttl = int(ip4Layer.TTL)
				tcpInfo.ACK = tcpLayer.ACK
				tcpInfo.CWR = tcpLayer.CWR
				tcpInfo.ECE = tcpLayer.ECE
				tcpInfo.FIN = tcpLayer.FIN
				tcpInfo.NS = tcpLayer.NS
				tcpInfo.PSH = tcpLayer.PSH
				tcpInfo.RST = tcpLayer.RST
				tcpInfo.SYN = tcpLayer.SYN
				tcpInfo.URG = tcpLayer.URG
				tcpInfo.windowSize = int(tcpLayer.Window)
				tcpInfo.options = readOptions(tcpLayer)
				tcpInfo.layer = tcpLayer
			case layers.LayerTypeUDP:
				contextInfo.transportProtocol = PROTOCOL_UDP
				contextInfo.localPort = uint16(udpLayer.SrcPort)
				// try parsing quic initial
				decrypted, connID, version, err := quic.DecryptQUICInitialPacket(udpLayer.LayerPayload())
				if err == nil {
					// detected QUIC Initial packet
					cryptoData := quic.GetInitialCryptoData(decrypted, connID, version)
					handshakeInfo, isPresent := ExtractHandshakeInfo(cryptoData, PROTOCOL_UDP)
					if isPresent && checkServiceSNI(service, handshakeInfo.GetServerName()) {
						// update transport layer info
						contextInfo.transportInfo.packetSize = packet.Metadata().CaptureLength
						contextInfo.transportInfo.ttl = int(ip4Layer.TTL)
						// update context attributes
						contextInfo.serverAddress.Url = handshakeInfo.GetServerName()
						contextInfo.chlo = handshakeInfo
						contexts = append(contexts, contextInfo)
					}
				}
			case layers.LayerTypeTLS:
				if contextInfo.transportProtocol == PROTOCOL_UDP {
					continue
				}
				// try extracting SNI from TLS header
				handshakeInfo, isPresent := ExtractHandshakeInfo(payload, PROTOCOL_TCP)
				if isPresent && checkServiceSNI(service, handshakeInfo.GetServerName()) {
					contextInfo.serverAddress.Url = handshakeInfo.GetServerName()
					contextInfo.transportInfo = tcpInfo
					contextInfo.chlo = handshakeInfo
					contexts = append(contexts, contextInfo)
				}
			}
		}
	}
	writeContextInfoToCsv(contexts, outPath)
}
