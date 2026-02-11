package main

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// AccessPoint represents a WiFi access point
type AccessPoint struct {
	BSSID    string `json:"bssid"`
	SSID     string `json:"ssid"`
	Channels []int  `json:"channels"`
	RSSI     int8   `json:"rssi"`
	Security string `json:"security"`
	SeenAt   int64  `json:"seen_at"`
}

// packetInfo holds extracted information from a single packet
type packetInfo struct {
	srcAddr      string
	dstAddr      string
	rssi         int8
	noise        int8
	snr          int8
	dataRate     uint8
	isDataFrame  bool
	isRetry      bool
	frameType    layers.Dot11Type
	frameSubType layers.Dot11Type
}

func getDot11Layer(packet gopacket.Packet) *layers.Dot11 {
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil
	}

	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return nil
	}

	return dot11
}

func getRadioTapLayer(packet gopacket.Packet) *layers.RadioTap {
	rtLayer := packet.Layer(layers.LayerTypeRadioTap)
	if rtLayer == nil {
		return nil
	}

	radioTap, ok := rtLayer.(*layers.RadioTap)
	if !ok {
		return nil
	}

	return radioTap
}

// scanForAccessPoints scans for WiFi access points by capturing beacon/probe response frames
// This method can get actual BSSIDs even on modern macOS where airport utility is deprecated
// and Swift Core WiFi utils require geo location permission to see BSSIDs
// channels: list of channels to scan (e.g., []int{1,6,11} for 2.4GHz)
// scanTime: time to spend on each channel (e.g., 500ms)
// Returns a map of BSSID -> AccessPoint
func scanForAccessPoints(iface string, channels []int, scanTime time.Duration, verbose bool) (map[string]AccessPoint, error) {
	accessPoints := make(map[string]AccessPoint)

	handle, err := pcap.OpenLive(iface, 65536, true, scanTime)
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
	if err := handle.SetBPFFilter("type mgt subtype beacon"); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	for _, channel := range channels {
		if err := setChannel(iface, channel); err != nil {
			fmt.Printf("Warning: failed to set channel %d: %v\n", channel, err)
			continue
		}

		if verbose {
			fmt.Printf("Scanning channel %d...\n", channel)
		}

		// Capture packets for scanTime on this channel
		deadline := time.Now().Add(scanTime)

		for time.Now().Before(deadline) {
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				fmt.Printf("Warning: error reading packet on channel %d: %v\n", channel, err)
				continue
			}

			packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)

			rTap := getRadioTapLayer(packet)
			if rTap == nil {
				continue
			}

			dot11 := getDot11Layer(packet)
			if dot11 == nil {
				continue
			}

			// Address3 is BSSID in beacon/probe frames
			bssid := dot11.Address3.String()
			ssid := extractSSIDFromBeacon(packet)
			_, enc, cipher, auth := dot11ParseEncryption(packet, dot11)

			if existing, ok := accessPoints[bssid]; ok {
				// Use last captured signal strength
				existing.RSSI = rTap.DBMAntennaSignal

				if !slices.Contains(existing.Channels, channel) {
					existing.Channels = append(existing.Channels, channel)
				}

				existing.SeenAt = ci.Timestamp.Unix()

				accessPoints[bssid] = existing
			} else {
				ap := AccessPoint{
					BSSID:    bssid,
					SSID:     ssid,
					Channels: []int{channel},
					RSSI:     rTap.DBMAntennaSignal,
					Security: fmt.Sprintf("%s %s %s", enc, cipher, auth),
					SeenAt:   ci.Timestamp.Unix(),
				}

				accessPoints[bssid] = ap
			}
		}
	}

	return accessPoints, nil
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

func joinInts(ints []int) string {
	str := ""
	for _, i := range ints {
		str += " " + strconv.Itoa(i)
	}
	return str
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
		fmt.Fprintf(w, "%s\t%s\t%s\t%d dBm\t%s\t\n", ap.BSSID, ssid, joinInts(ap.Channels), ap.RSSI, security)
	}
	fmt.Fprintln(w, "\t\t\t\t\t")
	w.Flush()

	fmt.Printf("\nTotal: %d access points\n", len(aps))
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

	// Determine frame type string
	// see https://en.wikipedia.org/wiki/802.11_frame_types#Types_and_subtypes
	info.frameType = dot11.Type.MainType()
	info.frameSubType = dot11.Type

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
