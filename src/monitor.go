package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	scribble "github.com/nanobox-io/golang-scribble"
)

// AccessPoint represents a WiFi access point discovered via beacon scanning
type AccessPoint struct {
	BSSID    string `json:"bssid"`
	SSID     string `json:"ssid"`
	Channel  int    `json:"channel"`
	RSSI     int8   `json:"rssi"`
	Security string `json:"security"`
	SeenAt   int64  `json:"seen_at"`
}

// SetChannel changes the channel of the network interface.
func setChannel(iface string, channel int) error {
	_, err := runSwift(setChannelSwift, iface, fmt.Sprintf("%d", channel))
	if err != nil {
		return fmt.Errorf("failed to set channel: %w", err)
	}

	return nil
}

// extractSSIDFromBeacon extracts SSID from 802.11 Information Elements
func extractSSIDFromBeacon(packet gopacket.Packet) string {
	dot11InfoLayer := packet.Layer(layers.LayerTypeDot11InformationElement)
	if dot11InfoLayer == nil {
		return ""
	}

	// Iterate through all information elements
	for _, layer := range packet.Layers() {
		if infoElem, ok := layer.(*layers.Dot11InformationElement); ok {
			if infoElem.ID == layers.Dot11InformationElementIDSSID {
				return string(infoElem.Info)
			}
		}
	}
	return ""
}

// extractRSSI attempts to extract RSSI from RadioTap header
func extractRSSI(packet gopacket.Packet) int8 {
	radioTapLayer := packet.Layer(layers.LayerTypeRadioTap)
	if radioTapLayer == nil {
		return -100
	}
	radioTap, ok := radioTapLayer.(*layers.RadioTap)
	if !ok {
		return -100
	}
	rssi := radioTap.DBMAntennaSignal
	// RSSI of 0 indicates the value wasn't set in the RadioTap header
	// Valid RSSI values are negative (typically -30 to -100 dBm)
	if rssi == 0 {
		return -100
	}
	return rssi
}

// parseRSNCipherSuite parses cipher suite from RSN/WPA IE
func parseRSNCipherSuite(suite []byte) string {
	if len(suite) < 4 {
		return ""
	}
	// Last byte indicates cipher type
	switch suite[3] {
	case 1:
		return "WEP-40"
	case 2:
		return "TKIP"
	case 4:
		return "CCMP"
	case 5:
		return "WEP-104"
	case 6:
		return "CMAC"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	default:
		return ""
	}
}

// parseAKMSuite parses authentication/key management suite
func parseAKMSuite(suite []byte) string {
	if len(suite) < 4 {
		return ""
	}
	// Check OUI (first 3 bytes)
	// 00:0F:AC = IEEE 802.11 (RSN)
	// 00:50:F2 = Microsoft (WPA)
	switch suite[3] {
	case 1:
		return "802.1X" // Enterprise
	case 2:
		return "PSK" // Personal
	case 3:
		return "FT-802.1X"
	case 4:
		return "FT-PSK"
	case 5:
		return "802.1X-SHA256"
	case 6:
		return "PSK-SHA256"
	case 8:
		return "SAE" // WPA3
	case 9:
		return "FT-SAE"
	case 12:
		return "OWE" // Enhanced Open
	case 18:
		return "SAE-SHA256" // WPA3
	default:
		return ""
	}
}

// parseRSNElement parses RSN (WPA2/WPA3) Information Element
func parseRSNElement(data []byte) (version string, ciphers []string, akms []string) {
	if len(data) < 8 {
		return "", nil, nil
	}

	// RSN Version (2 bytes) - should be 1
	rsnVersion := int(data[0]) | int(data[1])<<8
	if rsnVersion != 1 {
		return "", nil, nil
	}
	version = "RSN"

	// Group Cipher Suite (4 bytes)
	offset := 2
	if len(data) < offset+4 {
		return version, nil, nil
	}
	// Skip group cipher for now
	offset += 4

	// Pairwise Cipher Suite Count (2 bytes)
	if len(data) < offset+2 {
		return version, nil, nil
	}
	pairwiseCount := int(data[offset]) | int(data[offset+1])<<8
	offset += 2

	// Pairwise Cipher Suites
	for i := 0; i < pairwiseCount && len(data) >= offset+4; i++ {
		cipher := parseRSNCipherSuite(data[offset : offset+4])
		if cipher != "" {
			ciphers = append(ciphers, cipher)
		}
		offset += 4
	}

	// AKM Suite Count (2 bytes)
	if len(data) < offset+2 {
		return version, ciphers, nil
	}
	akmCount := int(data[offset]) | int(data[offset+1])<<8
	offset += 2

	// AKM Suites
	for i := 0; i < akmCount && len(data) >= offset+4; i++ {
		akm := parseAKMSuite(data[offset : offset+4])
		if akm != "" {
			akms = append(akms, akm)
		}
		offset += 4
	}

	return version, ciphers, akms
}

// Microsoft OUI for WPA
var microsoftOUI = []byte{0x00, 0x50, 0xF2}

// parseWPAElement parses WPA (legacy) vendor-specific Information Element
func parseWPAElement(data []byte) (version string, ciphers []string, akms []string) {
	// WPA IE structure:
	// OUI (3 bytes): 00:50:F2
	// OUI Type (1 byte): 01
	// Version (2 bytes)
	// Group Cipher (4 bytes)
	// Pairwise Count (2 bytes)
	// Pairwise Ciphers (4 bytes each)
	// AKM Count (2 bytes)
	// AKM Suites (4 bytes each)

	if len(data) < 8 {
		return "", nil, nil
	}

	// Check Microsoft OUI and type 1 (WPA)
	if data[0] != 0x00 || data[1] != 0x50 || data[2] != 0xF2 || data[3] != 0x01 {
		return "", nil, nil
	}

	version = "WPA"

	// WPA Version (2 bytes) - should be 1
	offset := 4
	if len(data) < offset+2 {
		return version, nil, nil
	}
	offset += 2

	// Group Cipher Suite (4 bytes)
	if len(data) < offset+4 {
		return version, nil, nil
	}
	offset += 4

	// Pairwise Cipher Suite Count (2 bytes)
	if len(data) < offset+2 {
		return version, nil, nil
	}
	pairwiseCount := int(data[offset]) | int(data[offset+1])<<8
	offset += 2

	// Pairwise Cipher Suites
	for i := 0; i < pairwiseCount && len(data) >= offset+4; i++ {
		cipher := parseRSNCipherSuite(data[offset : offset+4])
		if cipher != "" {
			ciphers = append(ciphers, cipher)
		}
		offset += 4
	}

	// AKM Suite Count (2 bytes)
	if len(data) < offset+2 {
		return version, ciphers, nil
	}
	akmCount := int(data[offset]) | int(data[offset+1])<<8
	offset += 2

	// AKM Suites
	for i := 0; i < akmCount && len(data) >= offset+4; i++ {
		akm := parseAKMSuite(data[offset : offset+4])
		if akm != "" {
			akms = append(akms, akm)
		}
		offset += 4
	}

	return version, ciphers, akms
}

// extractSecurityFromBeacon extracts security information from beacon/probe response
func extractSecurityFromBeacon(packet gopacket.Packet) string {
	var hasRSN, hasWPA bool
	var rsnAKMs, wpaAKMs []string
	var rsnCiphers, wpaCiphers []string
	var hasPrivacy bool

	// Check for privacy bit in capabilities (from Dot11MgmtBeacon or Dot11MgmtProbeResp)
	for _, layer := range packet.Layers() {
		switch l := layer.(type) {
		case *layers.Dot11MgmtBeacon:
			// Check privacy bit (bit 4 of capability info)
			hasPrivacy = (l.Flags & 0x0010) != 0
		case *layers.Dot11MgmtProbeResp:
			hasPrivacy = (l.Flags & 0x0010) != 0
		}
	}

	// Parse Information Elements
	for _, layer := range packet.Layers() {
		infoElem, ok := layer.(*layers.Dot11InformationElement)
		if !ok {
			continue
		}

		switch infoElem.ID {
		case layers.Dot11InformationElementIDRSNInfo: // RSN (WPA2/WPA3)
			_, ciphers, akms := parseRSNElement(infoElem.Info)
			if len(akms) > 0 || len(ciphers) > 0 {
				hasRSN = true
				rsnAKMs = akms
				rsnCiphers = ciphers
			}

		case layers.Dot11InformationElementIDVendor: // Vendor Specific (check for WPA)
			if len(infoElem.Info) >= 4 {
				_, ciphers, akms := parseWPAElement(infoElem.Info)
				if len(akms) > 0 || len(ciphers) > 0 {
					hasWPA = true
					wpaAKMs = akms
					wpaCiphers = ciphers
				}
			}
		}
	}

	// Build security string
	var parts []string

	if hasRSN {
		// Determine WPA2 vs WPA3
		isWPA3 := false
		for _, akm := range rsnAKMs {
			if akm == "SAE" || akm == "FT-SAE" || akm == "SAE-SHA256" || akm == "OWE" {
				isWPA3 = true
				break
			}
		}

		if isWPA3 {
			parts = append(parts, "WPA3")
		} else {
			parts = append(parts, "WPA2")
		}

		// Add auth type
		for _, akm := range rsnAKMs {
			switch akm {
			case "PSK", "PSK-SHA256", "FT-PSK":
				if !contains(parts, "Personal") {
					parts = append(parts, "Personal")
				}
			case "802.1X", "802.1X-SHA256", "FT-802.1X":
				if !contains(parts, "Enterprise") {
					parts = append(parts, "Enterprise")
				}
			case "SAE", "FT-SAE", "SAE-SHA256":
				if !contains(parts, "Personal") {
					parts = append(parts, "Personal")
				}
			case "OWE":
				parts = append(parts, "Enhanced Open")
			}
		}

		// Add cipher info
		for _, cipher := range rsnCiphers {
			if cipher == "CCMP" || cipher == "GCMP-128" || cipher == "GCMP-256" {
				if !contains(parts, "AES") {
					parts = append(parts, "AES")
				}
			}
		}
	}

	if hasWPA {
		if !hasRSN {
			parts = append(parts, "WPA")
		}
		for _, akm := range wpaAKMs {
			switch akm {
			case "PSK":
				if !contains(parts, "Personal") {
					parts = append(parts, "Personal")
				}
			case "802.1X":
				if !contains(parts, "Enterprise") {
					parts = append(parts, "Enterprise")
				}
			}
		}
		for _, cipher := range wpaCiphers {
			if cipher == "TKIP" && !contains(parts, "TKIP") {
				parts = append(parts, "TKIP")
			}
		}
	}

	// If privacy bit set but no WPA/RSN, it's WEP
	if hasPrivacy && !hasRSN && !hasWPA {
		return "WEP"
	}

	if len(parts) == 0 {
		if hasPrivacy {
			return "WEP"
		}
		return "Open"
	}

	return joinStrings(parts, " ")
}

// contains checks if a string slice contains a value
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// joinStrings joins strings with a separator
func joinStrings(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}

// scanForAccessPoints scans for WiFi access points by capturing beacon/probe response frames
// This method can get actual BSSIDs even on modern macOS where airport utility is deprecated
// and Swift Core WiFi utils require geo location permission to see BSSIDs
// channels: list of channels to scan (e.g., []int{1,6,11} for 2.4GHz)
// scanTime: time to spend on each channel (e.g., 500ms)
// Returns a map of BSSID -> AccessPoint
func scanForAccessPoints(iface string, channels []int, scanTime time.Duration, verbose bool) (map[string]AccessPoint, error) {
	accessPoints := make(map[string]AccessPoint)

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
	}
	defer handle.Close()

	// Set to capture IEEE802.11 radio packets (Monitor Mode)
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		return nil, fmt.Errorf("failed to set link type to monitor mode: %w", err)
	}

	// BPF filter for beacon and probe response frames
	// Type 0, Subtype 8 = Beacon
	// Type 0, Subtype 5 = Probe Response
	if err := handle.SetBPFFilter("type mgt subtype beacon or type mgt subtype probe-resp"); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	for _, channel := range channels {
		if err := setChannel(iface, channel); err != nil {
			if verbose {
				fmt.Printf("Warning: failed to set channel %d: %v\n", channel, err)
			}
			continue
		}

		if verbose {
			fmt.Printf("Scanning channel %d...\n", channel)
		}

		// Capture packets for scanTime on this channel
		deadline := time.Now().Add(scanTime)
		for time.Now().Before(deadline) {
			// Read packet with timeout
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				continue
			}

			packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)

			dot11Layer := packet.Layer(layers.LayerTypeDot11)
			if dot11Layer == nil {
				continue
			}

			dot11, ok := dot11Layer.(*layers.Dot11)
			if !ok {
				continue
			}

			// For beacon/probe response, Address2 is the BSSID (transmitter)
			// Address3 is also BSSID in these frames
			bssid := dot11.Address2.String()
			if bssid == "" || bssid == "00:00:00:00:00:00" {
				bssid = dot11.Address3.String()
			}

			if bssid == "" || bssid == "00:00:00:00:00:00" {
				continue
			}

			ssid := extractSSIDFromBeacon(packet)
			rssi := extractRSSI(packet)
			security := extractSecurityFromBeacon(packet)

			ap := AccessPoint{
				BSSID:    bssid,
				SSID:     ssid,
				Channel:  channel,
				RSSI:     rssi,
				Security: security,
				SeenAt:   ci.Timestamp.Unix(),
			}

			// Keep the one with strongest signal if we've seen this AP before
			if existing, exists := accessPoints[bssid]; exists {
				if rssi > existing.RSSI {
					accessPoints[bssid] = ap
				}
			} else {
				accessPoints[bssid] = ap
			}
		}
	}

	return accessPoints, nil
}

// getSecurityStrength returns a numeric value for security strength (lower = weaker)
func getSecurityStrength(security string) int {
	sec := strings.ToLower(security)

	// Open/Unknown - weakest
	if sec == "open" || sec == "unknown" || sec == "" {
		return 0
	}

	// WEP - very weak
	if strings.Contains(sec, "wep") {
		return 1
	}

	// WPA (legacy) - weak
	if strings.HasPrefix(sec, "wpa ") || sec == "wpa" {
		if strings.Contains(sec, "enterprise") {
			return 3
		}
		return 2
	}

	// WPA2 - moderate to strong
	if strings.Contains(sec, "wpa2") {
		if strings.Contains(sec, "enterprise") {
			return 5
		}
		return 4
	}

	// WPA3 - strongest
	if strings.Contains(sec, "wpa3") {
		if strings.Contains(sec, "enterprise") {
			return 7
		}
		return 6
	}

	// Default to middle strength if unknown format
	return 3
}

// sortAccessPoints converts map to slice and sorts by specified criteria
func sortAccessPoints(aps map[string]AccessPoint, sortType string) []AccessPoint {
	// Convert map to slice
	apList := make([]AccessPoint, 0, len(aps))
	for _, ap := range aps {
		apList = append(apList, ap)
	}

	if sortType == "security" {
		// Sort by security strength (weakest first), then by RSSI (strongest first) for ties
		sort.Slice(apList, func(i, j int) bool {
			strengthI := getSecurityStrength(apList[i].Security)
			strengthJ := getSecurityStrength(apList[j].Security)
			if strengthI != strengthJ {
				return strengthI < strengthJ // Weakest first
			}
			return apList[i].RSSI > apList[j].RSSI // Stronger signal first for ties
		})
	} else {
		// Sort by signal strength (strongest RSSI first - less negative = stronger)
		sort.Slice(apList, func(i, j int) bool {
			return apList[i].RSSI > apList[j].RSSI
		})
	}

	return apList
}

// printAccessPoints displays discovered access points in a formatted table
// sortByWeakSecurity: if true, sort by security (weakest first); if false, sort by RSSI (strongest first)
func printAccessPoints(aps map[string]AccessPoint, sort string) {
	if len(aps) == 0 {
		fmt.Println("No access points found")
		return
	}

	// Sort access points
	apList := sortAccessPoints(aps, sort)

	const padding = 2
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.AlignRight)

	fmt.Fprintln(w, "\nBSSID\tSSID\tChannel\tRSSI\tSecurity\t")
	fmt.Fprintln(w, "\t\t\t\t\t")
	for _, ap := range apList {
		ssid := ap.SSID
		if ssid == "" {
			ssid = "<hidden>"
		}
		security := ap.Security
		if security == "" {
			security = "Unknown"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d dBm\t%s\t\n", ap.BSSID, ssid, ap.Channel, ap.RSSI, security)
	}
	fmt.Fprintln(w, "\t\t\t\t\t")
	w.Flush()

	fmt.Printf("\nTotal: %d access points\n", len(aps))
}

// packetInfo holds extracted information from a single packet
type packetInfo struct {
	srcAddr     string
	dstAddr     string
	rssi        int8
	noise       int8
	snr         int8
	dataRate    uint8
	isDataFrame bool
	isRetry     bool
	frameType   string
}

// handlePacket extracts Dot11 and RadioTap layers from a packet
func handlePacket(p gopacket.Packet) (*layers.Dot11, *layers.RadioTap) {
	var dot11 *layers.Dot11
	var radioTap *layers.RadioTap

	if rtLayer := p.Layer(layers.LayerTypeRadioTap); rtLayer != nil {
		radioTap, _ = rtLayer.(*layers.RadioTap)
	}

	if d11Layer := p.Layer(layers.LayerTypeDot11); d11Layer != nil {
		dot11, _ = d11Layer.(*layers.Dot11)
	}

	return dot11, radioTap
}

// extractPacketInfo extracts all relevant information from Dot11 and RadioTap layers
func extractPacketInfo(dot11 *layers.Dot11, radioTap *layers.RadioTap) packetInfo {
	info := packetInfo{
		rssi:     -100,
		noise:    -100,
		dataRate: 0,
	}

	if dot11.Address1 != nil {
		info.dstAddr = dot11.Address1.String()
	}
	if dot11.Address2 != nil {
		info.srcAddr = dot11.Address2.String()
	}

	// Extract frame type information
	info.isDataFrame = dot11.Type.MainType() == layers.Dot11TypeData
	info.isRetry = dot11.Flags.Retry()

	// switch dot11.Type {
	// case layers.Dot11TypeMgmtAssociationResp:
	// 	// Handle association response
	// case layers.Dot11TypeMgmtBeacon:
	// 	// Handle beacon
	// case layers.Dot11TypeMgmtProbeReq:
	// 	// Handle probe request
	// }

	// Determine frame type string
	// see https://en.wikipedia.org/wiki/802.11_frame_types#Types_and_subtypes
	switch dot11.Type.MainType() {
	case layers.Dot11TypeData:
		info.frameType = "Data"
	case layers.Dot11TypeMgmt:
		info.frameType = "Mgmt"
	case layers.Dot11TypeCtrl:
		info.frameType = "Ctrl"
	default:
		info.frameType = "Unkn"
	}

	// Extract RadioTap information
	if radioTap != nil {
		info.rssi = radioTap.DBMAntennaSignal
		info.noise = radioTap.DBMAntennaNoise
		info.dataRate = uint8(radioTap.Rate)
	}
	info.snr = info.rssi - info.noise

	return info
}

// updateDevice updates or creates a device entry based on packet info
func updateDevice(devices map[string]device, info packetInfo) device {
	var dev device

	if existing, ok := devices[info.dstAddr]; ok {
		dev = existing
		dev.PCount++
		// Update RSSI with running average
		dev.AvgRSSI = int8((int(dev.AvgRSSI)*(dev.PCount-1) + int(info.rssi)) / dev.PCount)
		dev.LastRSSI = info.rssi
		dev.LastSeen = time.Now().Unix()
		if info.isRetry {
			dev.RetryCount++
		}
		if info.isDataFrame {
			dev.DataFrameCount++
		}
		if info.dataRate > dev.MaxDataRate {
			dev.MaxDataRate = info.dataRate
		}
		dev.SNR = info.snr
	} else {
		retryCount := 0
		if info.isRetry {
			retryCount = 1
		}
		dataFrameCount := 0
		if info.isDataFrame {
			dataFrameCount = 1
		}
		dev = device{
			Address:        info.dstAddr,
			PCount:         1,
			Rating:         0,
			AvgRSSI:        info.rssi,
			LastRSSI:       info.rssi,
			LastSeen:       time.Now().Unix(),
			RetryCount:     retryCount,
			DataFrameCount: dataFrameCount,
			MaxDataRate:    info.dataRate,
			SNR:            info.snr,
		}
	}

	return dev
}

// printPacketInfo prints real-time packet information as it arrives
func printPacketInfo(info packetInfo, dev device) {
	retryFlag := " "
	if info.isRetry {
		retryFlag = "R"
	}
	dataRateMbps := float64(info.dataRate) * 0.5
	fmt.Printf("[%s%s] %s -> %s | RSSI: %d dBm | SNR: %d | Rate: %.1f Mbps | Pkts: %d\n",
		info.frameType, retryFlag, info.srcAddr, info.dstAddr,
		info.rssi, info.snr, dataRateMbps, dev.PCount)
}

// printDeviceSummary prints a summary table of all discovered devices
func printDeviceSummary(devices map[string]device) {
	sortedDevices := sortDevices(devices)

	fmt.Printf("\n%s\n", strings.Repeat("-", 80))
	fmt.Printf("Total %d devices discovered\n\n", len(devices))

	const padding = 2
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.AlignRight)

	fmt.Fprintln(w, "Address\tPackets\tRSSI\tSNR\tDataRate\tRetry%\tData%\t")
	fmt.Fprintln(w, "\t\t\t\t\t\t\t")
	for _, d := range sortedDevices {
		retryPct := float64(0)
		if d.PCount > 0 {
			retryPct = float64(d.RetryCount) / float64(d.PCount) * 100
		}
		dataPct := float64(0)
		if d.PCount > 0 {
			dataPct = float64(d.DataFrameCount) / float64(d.PCount) * 100
		}
		// RadioTap Rate is in units of 500 Kbps, so multiply by 0.5 to get Mbps
		dataRateMbps := float64(d.MaxDataRate) * 0.5
		fmt.Fprintf(w, "%s\t%d\t%d dBm\t%d\t%.1f Mbps\t%.1f%%\t%.1f%%\t\n",
			d.Address, d.PCount, d.AvgRSSI, d.SNR, dataRateMbps, retryPct, dataPct)
	}
	fmt.Fprintln(w, "\t\t\t\t\t\t\t")
	w.Flush()
}

// openMonitorHandle opens a pcap handle configured for monitor mode
func openMonitorHandle(iface string, targetDevice string, currentMac string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	// Set to capture IEEE802.11 radio packets (Monitor Mode)
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		handle.Close()
		return nil, err
	}

	bpfFilter := fmt.Sprintf("ether src %s and not ether host ff:ff:ff:ff:ff:ff and not ether host %s", targetDevice, currentMac)
	fmt.Println("BPF Filter:", bpfFilter)

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, err
	}

	return handle, nil
}

func monitor(db *scribble.Driver, iface string, targetDevice string, channel int, maxNumPackets int) ([]device, error) {
	if err := setChannel(iface, channel); err != nil {
		return nil, err
	}

	currentMac, err := getMac(iface)
	if err != nil {
		return nil, err
	}

	handle, err := openMonitorHandle(iface, targetDevice, currentMac)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	devices := make(map[string]device)
	packetCount := 0

	for packet := range packetSource.Packets() {
		if packetCount > maxNumPackets {
			break
		}

		dot11, radioTap := handlePacket(packet)
		packetCount++

		if dot11 == nil || dot11.Address1 == nil {
			continue
		}

		info := extractPacketInfo(dot11, radioTap)
		if info.dstAddr == "" {
			continue
		}

		dev := updateDevice(devices, info)
		devices[info.dstAddr] = dev

		printPacketInfo(info, dev)

		if info.srcAddr != "" {
			db.Write(info.srcAddr, info.dstAddr, dev)
		}
	}

	printDeviceSummary(devices)

	return sortDevices(devices), nil
}
