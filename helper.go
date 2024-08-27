package main

import (
	"encoding/csv"
	"fmt"
	"github.com/google/gopacket/layers"
	"io/fs"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const COLORRESET = "\033[0m"
const COLORRED = "\033[31m"
const COLORGREEN = "\033[32m"
const COLORYELLOW = "\033[33m"
const COLORBLUE = "\033[34m"
const COLORPURPLE = "\033[35m"
const COLORCYAN = "\033[36m"
const COLORWHITE = "\033[37m"

const PROTOCOL_TCP = 6
const PROTOCOL_UDP = 17

type ServerAddress struct {
	Addr string `json:"addr"`
	Url  string `json:"url"`
}

type PacketData struct {
	payloadLength int
	timestamp     time.Time
	inbound       bool
}

func create(p string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(p), os.ModePerm); err != nil {
		return nil, err
	}
	return os.Create(p)
}

func writeToCsv(filePath string, records [][]string) {
	f, err := create(filePath)
	if err != nil {
		log.Fatalln("failed to open file", err)
	}
	w := csv.NewWriter(f)
	for _, record := range records {
		if err := w.Write(record); err != nil {
			log.Fatalln("error writing record to file", err)
		}
	}
	w.Flush()
	f.Close()
}

func contains(s []int64, e int64) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func bytesToInt16(byteSlice []byte) int {
	return int(byteSlice[0])<<8 + int(byteSlice[1])
}

func bytesToInt(bytes []byte) int {
	var sum int
	for i := range bytes {
		sum += int(bytes[i]) << (8 * (len(bytes) - i - 1))
	}
	return sum
}

func bytesToInt64(bytes []byte) int64 {
	var sum int64
	for i := range bytes {
		sum += int64(bytes[i]) << (8 * (len(bytes) - i - 1))
	}
	return sum
}

func getKeys(mymap map[int64]string) []int64 {
	keys := make([]int64, 0, len(mymap))
	for k := range mymap {
		keys = append(keys, k)
	}
	// sort before return, QUIC transport parameters extension is always the last one
	sort.Slice(keys, func(i, j int) bool {
		if keys[i] == 57 && keys[j] != 57 {
			return false
		} else if keys[i] != 57 && keys[j] == 57 {
			return true
		} else {
			return keys[i] < keys[j]
		}
	})
	return keys
}

func getProtocolFromNumber(num uint8) string {
	switch num {
	case PROTOCOL_TCP:
		return "tcp"
	case PROTOCOL_UDP:
		return "udp"
	default:
		return strconv.Itoa(int(num))
	}
}

func writeContextInfoToCsv(contexts []ContextInfo, path string) {
	for _, context := range contexts {
		savePath := fmt.Sprintf("%s/%s_%s_%s_%d.csv", path, context.serverAddress.Url, strings.ReplaceAll(context.serverAddress.Addr, ":", "-"),
			getProtocolFromNumber(context.transportProtocol), context.localPort)
		// concatenate transport & chlo strings
		results := append(context.chlo.ToCsvString(), context.transportInfo.toCsvString(context.transportProtocol)...)
		writeToCsv(savePath, results)
	}
}

func findFilesWithExtension(root, ext string) []string {
	var a []string
	filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == ext {
			a = append(a, s)
		}
		return nil
	})
	return a
}

func (transportInfo TransportInfo) toCsvString(protocol uint8) [][]string {
	// SYN packet matching requires additional resource in real time, so it is disabled by default
	var results [][]string
	results = append(results, []string{"packetSize", strconv.Itoa(transportInfo.packetSize), "TCP/IP"})
	results = append(results, []string{"ttl", strconv.Itoa(transportInfo.ttl), "TCP/IP"})
	if protocol == PROTOCOL_TCP {
		results = append(results, []string{"tcp_cwr", strconv.Itoa(Btoi(transportInfo.CWR)), "TCP/IP"})
		results = append(results, []string{"tcp_ece", strconv.Itoa(Btoi(transportInfo.ECE)), "TCP/IP"})
		results = append(results, []string{"tcp_urg", strconv.Itoa(Btoi(transportInfo.URG)), "TCP/IP"})
		results = append(results, []string{"tcp_ack", strconv.Itoa(Btoi(transportInfo.ACK)), "TCP/IP"})
		results = append(results, []string{"tcp_psh", strconv.Itoa(Btoi(transportInfo.PSH)), "TCP/IP"})
		results = append(results, []string{"tcp_rst", strconv.Itoa(Btoi(transportInfo.RST)), "TCP/IP"})
		results = append(results, []string{"tcp_syn", strconv.Itoa(Btoi(transportInfo.SYN)), "TCP/IP"})
		results = append(results, []string{"tcp_fin", strconv.Itoa(Btoi(transportInfo.FIN)), "TCP/IP"})
		results = append(results, []string{"tcp_window_size", strconv.Itoa(transportInfo.windowSize), "TCP/IP"})

		optionTypes := []layers.TCPOptionKind{layers.TCPOptionKindMSS, layers.TCPOptionKindWindowScale, layers.TCPOptionKindSACKPermitted}
		optionNames := map[layers.TCPOptionKind]string{
			layers.TCPOptionKindMSS:           "tcp_mss",
			layers.TCPOptionKindWindowScale:   "tcp_window_scale",
			layers.TCPOptionKindSACKPermitted: "tcp_sack_permitted",
		}
		for _, optionType := range optionTypes {
			option := findTCPOptionByType(transportInfo.options, optionType)
			name := optionNames[optionType]
			if option == nil {
				results = append(results, []string{name, "", "TCP/IP"})
			} else {
				switch optionType {
				case layers.TCPOptionKindMSS:
					results = append(results, []string{"tcp_mss", strconv.Itoa(bytesToInt(option.OptionData)), "TCP/IP"})
				case layers.TCPOptionKindWindowScale:
					results = append(results, []string{"tcp_window_scale",
						strconv.Itoa(powInt(2, bytesToInt(option.OptionData))), "TCP/IP"})
				case layers.TCPOptionKindSACKPermitted:
					results = append(results, []string{"tcp_sack_permitted", "1", "TCP/IP"})
				default:
				}
			}
		}
	}
	return results
}

func findTCPOptionByType(options []layers.TCPOption, optionType layers.TCPOptionKind) *layers.TCPOption {
	for _, option := range options {
		if option.OptionType == optionType {
			return &option
		}
	}
	return nil
}

func Btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func powInt(x, y int) int {
	return int(math.Pow(float64(x), float64(y)))
}

func readOptions(tcpLayer layers.TCP) []layers.TCPOption {
	var options []layers.TCPOption
	optionData := tcpLayer.LayerContents()[20:]
OPTIONS:
	for len(optionData) > 0 {
		opt := layers.TCPOption{
			OptionType: layers.TCPOptionKind(optionData[0]),
		}
		switch opt.OptionType {
		case layers.TCPOptionKindEndList: // End of options
			opt.OptionLength = 1
			options = append(options, opt)
			break OPTIONS
		case layers.TCPOptionKindNop: // 1 byte padding
			opt.OptionLength = 1
		default:
			if len(optionData) < 2 {
				panic("Invalid TCP option length, length less than 2")
			}
			opt.OptionLength = uint8(optionData[1])
			if opt.OptionLength < 2 {
				panic("Invalid TCP option length field, length less than 2")
			} else if int(opt.OptionLength) > len(optionData) {
				panic("Invalid TCP option length, length greater than remaining data")
			}
			opt.OptionData = optionData[2:opt.OptionLength]
		}
		options = append(options, opt)
		optionData = optionData[opt.OptionLength:]
	}
	return options
}

func checkServiceSNI(service string, sni string) bool {
	serviceMap := map[string][]string{
		"youtube": {"googlevideo.com"},
		"netflix": {"nflxvideo.net"},
		"amazon": {"avodmp4s3ww-a.akamaihd.net", "aiv-cdn.net", "pv-cdn.net", "aiv-delivery.net",
			"d1v5ir2lpwr8os.cloudfront.net", "d22qjgkvxw22r6.cloudfront.net", "d25xi40x97liuc.cloudfront.net",
			"d27xxe7juh1us6.cloudfront.net", "dmqdd6hw24ucf.cloudfront.net"},
		"disney": {"media.dssott.com", "dssedge.com"},
	}
	// for the given service, if the sni contains any of the strings as a substring, return true
	for _, s := range serviceMap[service] {
		if strings.HasSuffix(sni, s) {
			return true
		}
	}
	return false
}
