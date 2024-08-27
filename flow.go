package main

import (
	"crypto/tls"
	"time"
)

type Flow5Tuple struct {
	LocalAddr, RemoteAddr string
	LocalPort, RemotePort uint16
	Protocol              uint8
}

type Flow struct {
	flowStartTime, flowEndTime        time.Time
	packetsIn, packetsOut, packetsAll []PacketData
	flow5Tuple                        Flow5Tuple
	flowVolume                        int // byte size of the flow (incl. all headers)
	handshakeInfo                     HandshakeInfo
}

// GetFlowVolume returns the total byte size of all in/outbound packet incl. all headers
func (flow Flow) GetFlowVolume() int {
	return flow.flowVolume
}

// GetFlowDuration returns the flow duration in microseconds
func (flow Flow) GetFlowDuration() int64 {
	return flow.flowEndTime.Sub(flow.flowStartTime).Microseconds()
}

// GetPacketCounts returns totalCount, outCount, inCount
func (flow Flow) GetPacketCounts() (int, int, int) {
	totalCount := len(flow.packetsIn) + len(flow.packetsOut)
	return totalCount, len(flow.packetsOut), len(flow.packetsIn)
}

// DecodeCipherSuites returns names of the cipher suites
func DecodeCipherSuites(cipherSuites []byte) []string {
	// convert []byte to []int
	var cipherSuitesInt []int
	for i := 0; i < len(cipherSuites); i += 2 {
		cipherSuiteID := bytesToInt16(cipherSuites[i : i+2])
		cipherSuitesInt = append(cipherSuitesInt, cipherSuiteID)
	}
	// decode each integer code
	var cipherSuitesDecoded []string
	for _, suiteID := range cipherSuites {
		cipherSuitesDecoded = append(cipherSuitesDecoded, tls.CipherSuiteName(uint16(suiteID)))
	}
	return cipherSuitesDecoded
}
