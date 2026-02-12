package main

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
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

// scanForAccessPoints scans for WiFi access points by capturing beacon/probe response frames
// This method can get actual BSSIDs even on modern macOS where airport utility is deprecated
// and Swift Core WiFi utils require geo location permission to see BSSIDs
// channels: list of channels to scan (e.g., []int{1,6,11} for 2.4GHz)
// scanTime: time to spend on each channel (e.g., 500ms)
// updateChan: channel to send real-time updates to the UI
// channelChan: channel to send current channel updates
// Returns a map of BSSID -> AccessPoint
func scanForAccessPoints(iface string, channels []int, scanTime time.Duration, verbose bool, updateCh chan<- APUpdateMsg, channelCh chan<- ChannelUpdateMsg, errCh chan<- error) (map[string]AccessPoint, error) {
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
			errCh <- fmt.Errorf("failed to set channel %d: %v", channel, err)
			continue
		}

		// Send channel update
		if channelCh != nil {
			channelCh <- ChannelUpdateMsg{Channel: channel}
		}

		// Capture packets for scanTime on this channel
		deadline := time.Now().Add(scanTime)

		for time.Now().Before(deadline) {
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				errCh <- fmt.Errorf("error reading packet on channel %d: %v", channel, err)
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

			signal := rTap.DBMAntennaSignal
			if rTap.DBMAntennaSignal == 0 {
				signal = -100
			}

			if existing, ok := accessPoints[bssid]; ok {
				// Use last captured signal strength
				existing.RSSI = signal

				if !slices.Contains(existing.Channels, channel) {
					existing.Channels = append(existing.Channels, channel)
				}

				existing.SeenAt = ci.Timestamp.Unix()

				accessPoints[bssid] = existing
				// Send update
				if updateCh != nil {
					updateCh <- APUpdateMsg{BSSID: bssid, AP: existing}
				}
			} else {
				ap := AccessPoint{
					BSSID:    bssid,
					SSID:     ssid,
					Channels: []int{channel},
					RSSI:     signal,
					Security: fmt.Sprintf("%s %s %s", enc, cipher, auth),
					SeenAt:   ci.Timestamp.Unix(),
				}

				accessPoints[bssid] = ap
				// Send update
				if updateCh != nil {
					updateCh <- APUpdateMsg{BSSID: bssid, AP: ap}
				}
			}
		}
	}

	return accessPoints, nil
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
