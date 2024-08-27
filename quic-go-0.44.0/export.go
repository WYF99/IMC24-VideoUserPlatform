package quic

import (
	"errors"
	"fmt"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"time"
)

type quicHandshake struct {
	connectionID protocol.ConnectionID
	version      protocol.Version
	cryptoData   []byte
	cryptoStream cryptoStream
}

var quicCache = expirable.NewLRU[string, *quicHandshake](100, nil, time.Second*0)

// bytesToInt returns int value of a byte array with 4 bytes maximum
func bytesToInt(bytes []byte) int {
	var sum int
	for i, _ := range bytes {
		sum += int(bytes[i]) << ((len(bytes) - i - 1) * 8)
	}
	return sum
}

func DecryptQUICInitialPacket(payload []byte) ([]byte, protocol.ConnectionID, protocol.Version, error) {
	var destConnectionID protocol.ConnectionID
	// check if it is an Initial packet
	if !(len(payload) > 6 && payload[0]&0xf0 == 0xc0) {
		return nil, destConnectionID, 0, errors.New("not an INITIAL packet")
	}
	version := protocol.Version(bytesToInt(payload[1:5]))
	// check quic version compatibility
	if !protocol.IsValidVersion(version) {
		return nil, destConnectionID, 0, errors.New("Unsupported QUIC version: " + string(payload[1:5]))
	}
	// get length of connection ID field
	index := 5
	destConnectionIDLength := int(payload[5])
	if destConnectionIDLength > 20 {
		return nil, destConnectionID, 0, errors.New("invalid destination connection ID length")
	}
	index += 1
	// get destination connection ID
	destConnectionID = protocol.ParseConnectionID(payload[index : index+destConnectionIDLength])
	index += destConnectionIDLength
	// skip source connection ID
	sourceConnectionIDLength := int(payload[index])
	if sourceConnectionIDLength > 20 {
		return nil, destConnectionID, 0, errors.New("invalid source connection ID length")
	}
	index += 1 + sourceConnectionIDLength

	hdr, packetData, _, err := wire.ParsePacket(payload)
	if err != nil {
		return nil, destConnectionID, 0, err
	}

	_, initialOpener := handshake.NewInitialAEAD(destConnectionID, protocol.PerspectiveServer, version)
	if initialOpener == nil {
		return nil, destConnectionID, 0, errors.New("failed to create Initial opener")
	}

	extHdr, err := unpackLongHeader(initialOpener, hdr, packetData, version)
	if err != nil {
		return nil, destConnectionID, 0, err
	}

	extHdrLen := extHdr.ParsedLen()
	extHdr.PacketNumber = initialOpener.DecodePacketNumber(extHdr.PacketNumber, extHdr.PacketNumberLen)
	decrypted, err := initialOpener.Open(packetData[extHdrLen:extHdrLen], packetData[extHdrLen:], extHdr.PacketNumber, packetData[:extHdrLen])
	if err != nil {
		//fmt.Println(err.Error())
		return nil, destConnectionID, version, err
	}

	return decrypted, destConnectionID, version, nil
}

func GetInitialCryptoData(data []byte /*decrypted data*/, destConnectionID protocol.ConnectionID, version protocol.Version) []byte {
	var cryptoData []byte
	var str cryptoStream
	frameParser := wire.NewFrameParser(true) // TODO: decide whether or not support RFC9221
	// check if connection ID is in the cache
	if val, ok := quicCache.Get(destConnectionID.String()); ok {
		cryptoData = val.cryptoData
		str = val.cryptoStream
	} else {
		str = newCryptoStream()
	}

	for len(data) > 0 {
		l, f, err := frameParser.ParseNext(data, protocol.EncryptionInitial, version)
		if err != nil {
			fmt.Println(err.Error())
			return nil
		}
		data = data[l:]
		if f == nil {
			break
		}
		// handle frame
		switch frame := f.(type) {
		case *wire.CryptoFrame:
			err = str.HandleCryptoFrame(frame)
			if err != nil {
				fmt.Println(err.Error())
			}
		case *wire.PingFrame:
		case *wire.AckFrame:
		default:
		}
	}

	// check for incomplete crypto data (split across multiple packets)
	cryptoData = append(cryptoData, str.GetCryptoData()...) // Get will erase msgBuf in str
	if len(cryptoData) > 4 && cryptoData[0] == 0x01 {
		// handshake message
		if bytesToInt(cryptoData[1:4])+4 == len(cryptoData) {
			// crypto data is complete
			quicCache.Remove(destConnectionID.String())
			return cryptoData
		} else {
			// crypto data is incomplete, expect crypto frames in subsequent packets
			// store the crypto stream for later use
			quicCache.Add(destConnectionID.String(), &quicHandshake{
				connectionID: destConnectionID,
				version:      version,
				cryptoData:   cryptoData,
				cryptoStream: str,
			})
			// return nil as if no crypto data is available
			return nil
		}
	} else {
		return nil
	}
}
