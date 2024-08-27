package main

import (
	"encoding/hex"
	"fmt"
	"math"
)

type Extension struct {
	code   int64
	length int
	value  []byte
}

type HandshakeInfo struct {
	length             int
	version            []byte
	cipherSuites       []byte
	compressionMethods []byte
	extensionsLength   int
	extensions         []Extension
}

var ExtensionGreaseValues = []int64{0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}

func ExtractHandshakeInfo(payload []byte, protocol uint8) (HandshakeInfo, bool) {
	// processing is the same for TCP and QUIC afterwards
	var info HandshakeInfo
	pLen := len(payload)
	info.length = pLen
	// QUIC TLS record does not contain TLS record layer metadata, hence pad 5 bytes in front
	if protocol == PROTOCOL_UDP {
		payload = append([]byte{0x16, 0, 0, 0, 0}, payload...)
		pLen += 5
	}
	// Check if the packet is a Client Hello,
	// 43 mandatory bytes before session ID length, 55 mandatory bytes in total
	if !(pLen > 55 && payload[0] == 0x16 && payload[5] == 0x01) {
		return info, false
	}
	// get record length, in case multiple TLS records are in the same packet
	if protocol == PROTOCOL_TCP {
		pLen = bytesToInt16(payload[3:5]) + 5
	}
	// Extract version string
	info.version = payload[9:11]
	// Skip over <Session IDs>
	sessionIdLength := int((payload[43]))
	index := 44 + sessionIdLength
	if index >= pLen || index+2 > pLen {
		return info, false
	}
	// Extract <Cipher Suite Length>
	cipherSuitesLength := bytesToInt16(payload[index : index+2])
	// Skip over <Cipher Suite Length>
	index += 2
	// Extract <Cipher Suites>
	var cipherSuites []byte
	if index+cipherSuitesLength > pLen {
		return info, false
	}
	cipherSuites = handleGreaseFromExtensionValue(payload[index : index+cipherSuitesLength])
	info.cipherSuites = cipherSuites
	index += cipherSuitesLength
	if index >= pLen {
		return info, false
	}
	// Extract <Compression Methods Length>
	compressionMethodsLength := int(payload[index])
	// Skip over compression length
	index += 1
	// Extract <Compression Methods>
	if index >= pLen || index+compressionMethodsLength > pLen {
		return info, false
	}
	info.compressionMethods = payload[index : index+compressionMethodsLength]
	index += compressionMethodsLength
	if index >= pLen || index+2 > pLen {
		return info, false
	}
	// Extract <Extensions Length>
	info.extensionsLength = bytesToInt16(payload[index : index+2])
	// Skip over <Extensions Length>
	index += 2
	if index >= pLen {
		return info, false
	}
	// Extract every extension
	for index < pLen {
		var extension Extension
		if index+2 > pLen {
			return info, false
		}
		extension.code = bytesToInt64(payload[index : index+2])
		index += 2
		if index >= pLen || index+2 > pLen {
			return info, false
		}
		extension.length = bytesToInt16(payload[index : index+2])
		index += 2
		if index >= pLen {
			return info, false
		}
		if extension.length > 0 {
			if index+extension.length > pLen {
				//fmt.Println("Error: extension length exceeds packet length", "extension code =", extension.code,
				//	"extension length =", extension.length, "packet length =", pLen)
				return info, false
			}
			extension.value = payload[index : index+extension.length]
		}
		info.extensions = append(info.extensions, extension)
		index += extension.length
	}

	return info, true
}

func findExtensionByCode(extensions []Extension, code int64) *Extension {
	for _, extension := range extensions {
		if extension.code == code {
			return &extension
		}
	}
	return nil
}

func ExtensionsToStrings(extensions []Extension) [][]string {
	extensionCodes := map[int64]string{
		0:     "server_name",
		5:     "status_request",
		10:    "supported_groups",
		11:    "ec_point_formats",
		13:    "signature_algorithms",
		16:    "application_layer_protocol_negotiation",
		18:    "signed_certificate_timestamp",
		21:    "padding", // keep it or not?
		22:    "encrypt_then_mac",
		23:    "extended_master_secret",
		27:    "compress_certificate",
		28:    "record_size_limit",
		34:    "delegated_credentials",
		35:    "session_ticket",
		41:    "pre_shared_key",
		42:    "early_data",
		43:    "supported_versions",
		45:    "psk_key_exchange_modes",
		49:    "post_handshake_auth",
		51:    "key_share",
		65281: "renegotiation_info",
		17513: "application_settings",
		57:    "quic_transport_parameters",
	}
	var results [][]string
	results = append(results, []string{"extensions_list", convertExtensionListToString(extensions), "TLS extensions"})

	for _, code := range getKeys(extensionCodes) {
		name := extensionCodes[code]
		extension := findExtensionByCode(extensions, code)
		if extension == nil {
			if code == 57 {
				// skip QUIC transport parameters for TCP
				continue
			} else if contains([]int64{10, 13, 16, 34, 43, 51, 17513}, code) {
				results = append(results, []string{name + "_length", "", "TLS extensions"})
				results = append(results, []string{name + "_list", "", "TLS extensions"})
			} else {
				results = append(results, []string{name, "", "TLS extensions"})
			}
			continue
		}

		switch code {
		case 0: // server_name, return 1 if present
			results = append(results, []string{name, "1", "TLS extensions"})
		case 5: // status_request, return raw byte value
			results = append(results, []string{name, fmt.Sprintf("%x", extension.value), "TLS extensions"})
		case 10: // supported_groups, return numerical length and categorical list
			// first two bytes are length
			groupsLength := bytesToInt(extension.value[0:2])
			results = append(results, []string{name + "_length", fmt.Sprintf("%d", groupsLength), "TLS extensions"})
			// uniformise GREASE before output
			results = append(results, []string{name + "_list", convertListToString(handleGreaseFromExtensionValue(extension.value[2:2+groupsLength]), false), "TLS extensions"})
		case 11: // ec_point_formats, return raw byte value
			results = append(results, []string{name, fmt.Sprintf("%x", extension.value), "TLS extensions"})
		case 13: // signature_algorithms, return numerical length and categorical list
			// first two bytes are length
			valueLength := bytesToInt(extension.value[0:2])
			results = append(results, []string{name + "_length", fmt.Sprintf("%d", valueLength), "TLS extensions"})
			results = append(results, []string{name + "_list", convertListToString(handleGreaseFromExtensionValue(extension.value[2:2+valueLength]), false), "TLS extensions"})
		case 16: // application_layer_protocol_negotiation, return numerical length and categorical list
			// first two bytes are length, assuming extension value length > 0
			valueLength := bytesToInt(extension.value[0:2])
			var numProtocols int
			for i := 2; i < valueLength+2; {
				protocolLength := int(extension.value[i])
				i += 1 + protocolLength
				numProtocols++
			}
			results = append(results, []string{name + "_length", fmt.Sprintf("%d", numProtocols), "TLS extensions"})
			results = append(results, []string{name + "_list", convertListToString(extension.value[2:2+valueLength], true), "TLS extensions"})
		case 18: // signed_certificate_timestamp, return 1 if present
			results = append(results, []string{name, "1", "TLS extensions"})
		case 21: // padding, return padding length
			results = append(results, []string{name, fmt.Sprintf("%d", extension.length), "TLS extensions"})
		case 22: // encrypt_then_mac, return 1 if present
			results = append(results, []string{name, "1", "TLS extensions"})
		case 23: // extended_master_secret, return 1 if present
			results = append(results, []string{name, "1", "TLS extensions"})
		case 27: // compress_certificate, return raw byte value for the algorithm only
			// first byte is length
			valueLength := int(extension.value[0])
			results = append(results, []string{name, fmt.Sprintf("%x", extension.value[1:1+valueLength]), "TLS extensions"})
		case 28: // record_size_limit, return numerical value
			// fixed length of 2 bytes
			results = append(results, []string{name, fmt.Sprintf("%d", bytesToInt(extension.value)), "TLS extensions"})
		case 34: // delegated_credentials, return numerical length and categorical list
			// first two bytes are length
			valueLength := bytesToInt(extension.value[0:2])
			results = append(results, []string{name + "_length", fmt.Sprintf("%d", valueLength), "TLS extensions"})
			results = append(results, []string{name + "_list", convertListToString(handleGreaseFromExtensionValue(extension.value[2:2+valueLength]), false), "TLS extensions"})
		case 35: // session_ticket, return numerical length
			results = append(results, []string{name, fmt.Sprintf("%d", extension.length), "TLS extensions"})
		case 41: // pre_shared_key, return 1 if present
			results = append(results, []string{name, "1", "TLS extensions"})
		case 42: // early_data, return numerical length
			results = append(results, []string{name, fmt.Sprintf("%d", extension.length), "TLS extensions"})
		case 43: // supported_versions, return numerical length and categorical list
			// first byte is length
			valueLength := int(extension.value[0])
			results = append(results, []string{name + "_length", fmt.Sprintf("%d", valueLength), "TLS extensions"})
			results = append(results, []string{name + "_list", convertListToString(handleGreaseFromExtensionValue(extension.value[1:1+valueLength]), false), "TLS extensions"})
		case 45: // psk_key_exchange_modes, return mode code only
			// first byte is length, assuming it's always 1
			valueLength := int(extension.value[0])
			if valueLength != 1 {
				fmt.Println(COLORYELLOW + "Handle " + name + " extension!" + COLORRESET)
			}
			results = append(results, []string{name, fmt.Sprintf("%x", extension.value[1:1+valueLength]), "TLS extensions"})
		case 49: // post_handshake_auth, return 1 if present
			results = append(results, []string{name, "1", "TLS extensions"})
		case 51: // key_share, return numerical length and categorical list
			// first two bytes are length
			valueLength := bytesToInt(extension.value[0:2])
			results = append(results, []string{name + "_length", fmt.Sprintf("%d", valueLength), "TLS extensions"})
			// for the categorical values, use group ID only (2 bytes each)
			var keyShare []byte
			for i := 2; i < valueLength+2; {
				groupID := bytesToInt64(extension.value[i : i+2])
				if contains(ExtensionGreaseValues, groupID) {
					groupID = 0x0a0a
				}
				keyShare = append(keyShare, byte(groupID>>8))
				keyShare = append(keyShare, byte(groupID))
				// skip over group ID
				i += 2
				keyExchangeLength := bytesToInt(extension.value[i : i+2])
				// skip over key exchange length and key exchange
				i += 2 + keyExchangeLength
			}
			results = append(results, []string{name + "_list", convertListToString(keyShare, false), "TLS extensions"})
		case 17513: // application settings, return numerical length and categorical list
			// first two bytes are length, assuming extension value length > 0
			valueLength := bytesToInt(extension.value[0:2])
			var numProtocols int
			for i := 2; i < valueLength+2; {
				protocolLength := int(extension.value[i])
				i += 1 + protocolLength
				numProtocols++
			}
			results = append(results, []string{name + "_length", fmt.Sprintf("%d", numProtocols), "TLS extensions"})
			results = append(results, []string{name + "_list", convertListToString(extension.value[2:2+valueLength], true), "TLS extensions"})
		case 65281: // renegotiation_info, return 1 if present
			// extension data should always be 0x00 in Initial ClientHello
			if extension.length > 1 || extension.value[0] != 0x00 {
				fmt.Println(COLORYELLOW + "Handle " + name + " extension!" + COLORRESET)
			}
			results = append(results, []string{name, "1", "TLS extensions"})
		case 57: // quic_transport_parameters
			// convert raw data to extensions
			var transportParams []Extension
			for i := 0; i < extension.length; {
				var param Extension
				// both paramCode and paramLength are variable length integers
				codeLength, paramCode := parseVariableLengthInteger(extension.value[i:])
				param.code = paramCode
				i += codeLength
				lengthFieldLength, paramLength := parseVariableLengthInteger(extension.value[i:])
				param.length = int(paramLength)
				i += lengthFieldLength
				param.value = extension.value[i : i+param.length]
				i += param.length
				transportParams = append(transportParams, param)
			}
			// convert parameters to strings
			parsedStrings := parseQUICTransportParameters(transportParams)
			results = append(results, parsedStrings...)
		}
	}
	// print if some extensions are not covered
	for _, extension := range extensions {
		if !contains(getKeys(extensionCodes), extension.code) && !contains(ExtensionGreaseValues, extension.code) {
			fmt.Println(COLORCYAN, "Found new extension code", extension.code, COLORRESET)
		}
	}
	return results
}

func parseQUICTransportParameters(parameters []Extension) [][]string {
	//paramCodes := []int64{0x01,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0c,0x0e,0x0f,0x20,0x2ab2,0x3128,0x4752,0xff73db}
	paramCodes := map[int64]string{
		0x01:     "max_idle_timeout",
		0x03:     "max_udp_payload_size",
		0x04:     "initial_max_data",
		0x05:     "initial_max_stream_data_bidi_local",
		0x06:     "initial_max_stream_data_bidi_remote",
		0x07:     "initial_max_stream_data_uni",
		0x08:     "initial_max_streams_bidi",
		0x09:     "initial_max_streams_uni",
		0x0b:     "max_ack_delay",
		0x0c:     "disable_active_migration",
		0x0e:     "active_connection_id_limit",
		0x0f:     "initial_source_connection_id",
		0x20:     "max_datagram_frame_size",
		0x2ab2:   "grease_quic_bit",
		0x3127:   "initial_rtt",
		0x3128:   "google_connection_options",
		0x3129:   "user_agent", // deprecated
		0x4752:   "google_version",
		0xff73db: "version_information",
	}
	var results [][]string
	results = append(results, []string{"parameters_list", convertExtensionListToString(parameters), "QUIC transport parameters"})

	for _, code := range getKeys(paramCodes) {
		name := paramCodes[code]
		parameter := findExtensionByCode(parameters, code)
		if parameter == nil {
			if contains([]int64{0x3128, 0xff73db}, code) {
				results = append(results, []string{name + "_length", "", "QUIC transport parameters"})
				results = append(results, []string{name + "_value", "", "QUIC transport parameters"})
			} else {
				results = append(results, []string{name, "", "QUIC transport parameters"})
			}
			continue
		}

		switch code {
		case 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0e, 0x20: // parameters with variable length value, return decimal value
			valueLength, paramValue := parseVariableLengthInteger(parameter.value)
			if valueLength != parameter.length {
				panic("parsed value length does not match length field of parameter " + name)
			}
			results = append(results, []string{name, fmt.Sprintf("%d", paramValue), "QUIC transport parameters"})
		case 0x0c: // disable_active_migration, return 1 if present
			results = append(results, []string{name, "1", "QUIC transport parameters"})
		case 0x0f: // initial_source_connection_id, return the length only
			results = append(results, []string{name, fmt.Sprintf("%d", parameter.length), "QUIC transport parameters"})
		case 0x2ab2: // grease_quic_bit, return 1 if present
			results = append(results, []string{name, "1", "QUIC transport parameters"})
		case 0x3127: // initial_rtt, return 1 if present
			results = append(results, []string{name, "1", "QUIC transport parameters"})
		case 0x3128: // google_connection_options, return numerical length and categorical value
			results = append(results, []string{name + "_length", fmt.Sprintf("%d", parameter.length), "QUIC transport parameters"})
			results = append(results, []string{name + "_value", fmt.Sprintf("%x", parameter.value), "QUIC transport parameters"})
		case 0x3129: // user_agent, return raw byte value
			results = append(results, []string{name, fmt.Sprintf("%x", parameter.value), "QUIC transport parameters"})
		case 0x4752: // google_quic_version, return raw byte value
			// fixed 4-byte length
			results = append(results, []string{name, fmt.Sprintf("%x", parameter.value), "QUIC transport parameters"})
		case 0xff73db: // version_information, return numerical length and categorical value
			// handle GREASE versions, each version is 4 bytes
			var versions []byte
			for i := 0; i < parameter.length; i += 4 {
				version := parameter.value[i : i+4]
				versionString := hex.EncodeToString(version)
				if versionString[1] == 'a' && versionString[3] == 'a' && versionString[5] == 'a' && versionString[7] == 'a' {
					// GREASE version matches pattern "?a?a?a?a"
					version = []byte{0x0a, 0x0a, 0x0a, 0x0a}
				}
				versions = append(versions, version...)
			}
			results = append(results, []string{name + "_length", fmt.Sprintf("%d", parameter.length), "QUIC transport parameters"})
			results = append(results, []string{name + "_value", fmt.Sprintf("%x", versions), "QUIC transport parameters"})
		}
		// print if some extensions are not covered
		for _, parameter := range parameters {
			if !contains(getKeys(paramCodes), parameter.code) && (parameter.code-27)%31 != 0 {
				fmt.Println(COLORCYAN, "Found new parameter code", parameter.code, COLORRESET)
			}
		}
	}
	return results
}

func (info HandshakeInfo) GetServerName() string {
	var serverName string
	for _, extension := range info.extensions {
		if extension.code == 0 {
			index := 2 // skip server name list length
			if extension.value[2] == 0 {
				// server name type: host name
				index += 1
				sniLength := bytesToInt16(extension.value[index : index+2])
				index += 2
				serverName = string(extension.value[index : index+sniLength])
				return serverName
			}
		}
	}
	return serverName
}

func (info HandshakeInfo) GetVersion() string {
	if bytesToInt(info.version) == 0x0303 {
		for _, extension := range info.extensions {
			if extension.code == 43 {
				// found supported versions extension
				return "TLS 1.3"
			}
		}
		return "TLS 1.2"
	} else {
		fmt.Println(COLORRED+"Unhandled version number ", info.version, COLORRESET)
		return fmt.Sprintf("unrecognised version %d", info.version)
	}
}

func (info HandshakeInfo) ToCsvString() [][]string {
	var results [][]string
	results = append(results, []string{"handshake_length", fmt.Sprintf("%d", info.length), "TLS mandatory"})
	results = append(results, []string{"TLS_version", fmt.Sprintf("%x", info.version), "TLS mandatory"})
	results = append(results, []string{"cipher_suites_length", fmt.Sprintf("%d", len(info.cipherSuites)), "TLS mandatory"})
	results = append(results, []string{"cipher_suites_list", convertListToString(info.cipherSuites, false), "TLS mandatory"})
	results = append(results, []string{"compression_methods_length", fmt.Sprintf("%d", len(info.compressionMethods)), "TLS mandatory"})
	results = append(results, []string{"extensions_length", fmt.Sprintf("%d", info.extensionsLength), "TLS mandatory"})
	results = append(results, ExtensionsToStrings(info.extensions)...)
	return results
}

func parseVariableLengthInteger(data []byte) (int /*integer length*/, int64 /*parsed data*/) {
	// extract length from the 2 msb
	msb2 := int((data[0] & 0xc0) >> 6)
	length := int(math.Pow(2, float64(msb2)))
	if len(data) < length {
		panic("parsed integer length does not match data length")
	}
	// parse <length> bytes of data
	var newData []byte
	for i := 0; i < length; i += 1 {
		if i == 0 {
			newData = append(newData, data[i]&0x3f)
		} else {
			newData = append(newData, data[i])
		}
	}
	return length, bytesToInt64(newData)
}

func handleGreaseFromExtensionValue(data []byte) []byte {
	var result []byte
	for i := 0; i < len(data); i += 2 {
		cipherSuite := bytesToInt64(data[i : i+2])
		if contains(ExtensionGreaseValues, cipherSuite) {
			// replace all GREASE values with 0x0a0a
			cipherSuite = 0x0a0a
		}
		result = append(result, byte(cipherSuite>>8))
		result = append(result, byte(cipherSuite))
	}
	return result
}

func convertListToString(list []byte, variableLength bool) string {
	// each item is separated by | in the resulting string
	var result string
	if variableLength {
		// application_layer_protocol_negotiation_list or application_settings_list
		// each item is preceded by a 1-byte length
		for i := 0; i < len(list); i += 1 + int(list[i]) {
			length := int(list[i])
			num := bytesToInt64(list[i+1 : i+1+length])
			result += fmt.Sprintf("%d|", num)
		}
	} else {
		// otherwise 2 bytes per item
		for i := 0; i < len(list); i += 2 {
			num := bytesToInt(list[i : i+2])
			result += fmt.Sprintf("%d|", num)
		}
	}
	// remove the last |
	if len(result) > 0 {
		result = result[:len(result)-1]
	}
	return result
}

func convertExtensionListToString(list []Extension) string {
	var result string
	for _, extension := range list {
		if contains(ExtensionGreaseValues, extension.code) {
			// replace all GREASE values with 0x0a0a
			extension.code = 0x0a0a
		}
		result += fmt.Sprintf("%d|", extension.code)
	}
	// remove the last |
	if len(result) > 0 {
		result = result[:len(result)-1]
	}
	return result
}
