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
	return radioTap.DBMAntennaSignal
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

// ScanForAccessPoints scans for WiFi access points by capturing beacon/probe response frames
// This method can get actual BSSIDs even on modern macOS where airport utility is deprecated
// and Swift Core WiFi utils require geo location permission to see BSSIDs
// channels: list of channels to scan (e.g., []int{1,6,11} for 2.4GHz)
// dwellTime: time to spend on each channel (e.g., 500ms)
// Returns a map of BSSID -> AccessPoint
func ScanForAccessPoints(iface string, channels []int, dwellTime time.Duration) (map[string]AccessPoint, error) {
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
			if *verbose {
				fmt.Printf("Warning: failed to set channel %d: %v\n", channel, err)
			}
			continue
		}

		if *verbose {
			fmt.Printf("Scanning channel %d...\n", channel)
		}

		// Capture packets for dwellTime on this channel
		deadline := time.Now().Add(dwellTime)
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

// SortAccessPoints converts map to slice and sorts by specified criteria
func SortAccessPoints(aps map[string]AccessPoint, byWeakSecurity bool) []AccessPoint {
	// Convert map to slice
	apList := make([]AccessPoint, 0, len(aps))
	for _, ap := range aps {
		apList = append(apList, ap)
	}

	if byWeakSecurity {
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

// PrintAccessPoints displays discovered access points in a formatted table
// sortByWeakSecurity: if true, sort by security (weakest first); if false, sort by RSSI (strongest first)
func PrintAccessPoints(aps map[string]AccessPoint, sortByWeakSecurity bool) {
	if len(aps) == 0 {
		fmt.Println("No access points found")
		return
	}

	// Sort access points
	apList := SortAccessPoints(aps, sortByWeakSecurity)

	const padding = 2
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.AlignRight)

	sortLabel := "(sorted by signal strength)"
	if sortByWeakSecurity {
		sortLabel = "(sorted by security - weakest first)"
	}
	fmt.Printf("\n%s\n\n", sortLabel)

	fmt.Fprintln(w, "BSSID\tSSID\tChannel\tRSSI\tSecurity\t")
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

func handlePacket(p gopacket.Packet) *layers.Dot11 {
	linkLayer := p.Layer(layers.LayerTypeDot11)
	if linkLayer != nil {
		// Get actual dot11 data from this layer
		dot11, _ := linkLayer.(*layers.Dot11)
		return dot11
	}
	return nil
}

func monitor(db *scribble.Driver, iface string, targetDevice string, channel int, maxNumPackets int) ([]device, error) {
	err := setChannel(iface, channel)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// Set to capture IEEE802.11 radio packets (Monitor Mode)
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		return nil, err
	}

	currentMac, err := getMac(iface)
	if err != nil {
		return nil, err
	}

	bpfFilter := fmt.Sprintf("ether src %s and not ether host ff:ff:ff:ff:ff:ff and not ether host %s", targetDevice, currentMac)
	// bpfFilter := ""

	if *verbose {
		fmt.Println("BPF Filter: ", bpfFilter)
	}

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	devices := make(map[string]device)
	packetCount := 0

	for packet := range packetSource.Packets() {
		if packetCount > maxNumPackets {
			handle.Close()
			break
		}

		chunk := handlePacket(packet)
		packetCount++

		if chunk == nil {
			continue
		}

		dstAddr := chunk.Address1
		srcAddr := chunk.Address2

		if dstAddr == nil {
			continue
		}

		var newDevice device

		if val, ok := devices[dstAddr.String()]; ok {
			val.PCount++
			newDevice = val
		} else {
			newDevice = device{
				Address: dstAddr.String(),
				PCount:  1,
				Rating:  0,
			}
		}

		if *verbose {
			fmt.Printf("%s %d\n", dstAddr, newDevice.PCount)
		}

		devices[dstAddr.String()] = newDevice

		db.Write(srcAddr.String(), dstAddr.String(), newDevice)
	}

	sortedDevices := sortDevices(devices)
	if *verbose {
		fmt.Printf("\nTotal %d devices discovered\n\n", len(devices))

		const padding = 4
		w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.AlignRight)

		fmt.Fprintln(w, "Address\tPackets\t")
		fmt.Fprintln(w, "\t")
		for _, d := range sortedDevices {
			fmt.Fprintf(w, "%s\t%d\t\n", d.Address, d.PCount)
		}
		fmt.Fprintln(w, "\t")
		w.Flush()
	}

	return sortedDevices, nil
}
