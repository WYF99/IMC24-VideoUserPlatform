package main

import (
	_ "errors"
	"flag"
	"fmt"
	_ "net"
	"os"
	"strings"
	"time"
)

var (
	service     string
	path        string
	device      string
	application string
	outPath     string
)

func getUserPlatformFromPath(filePath string) (string, string) {
	if strings.Contains(filePath, "/") {
		return strings.Split(filePath, "/")[3], strings.Split(strings.Split(filePath, "/")[4], ".")[0]
	} else if strings.Contains(filePath, "\\") {
		return strings.Split(filePath, "\\")[3], strings.Split(strings.Split(filePath, "\\")[4], ".")[0]
	}
	return "", ""
}

func main() {
	startTime := time.Now()
	flag.StringVar(&service, "s", "youtube", "video service provider name")
	flag.StringVar(&path, "p", "../"+service+"_collection/pcap", "path to pcap files")
	// assume each directory contains pcap files for a specific user platform
	// e.g., ../../youtube_collection/pcap/win/chrome.pcapng
	dirs, _ := os.ReadDir(path)
	for _, dir := range dirs {
		filePath := path + "/" + dir.Name()
		for _, fileName := range findFilesWithExtension(filePath, ".pcapng") {
			device, application = getUserPlatformFromPath(fileName)
			outPath = fmt.Sprintf("../"+service+"_collection/context_csv/%s_%s", device, application)
			ExtractContextAttributes(fileName, service, device, application, outPath)
		}
	}
	endTime := time.Now()
	fmt.Println("Time taken: ", endTime.Sub(startTime))
}
