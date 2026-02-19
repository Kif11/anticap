package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TODO:
// [ ] Add support for continues scanning channels
// [ ] Verify that handshake capture works
// [ ] Cleanup some brodcasting packets in the result
// [ ] Find out why some BSSID show up as hidden
// [ ] Improve sorting

type channelStats struct {
	numPackets int
}

type Discovery struct {
	APs        map[string]AccessPoint
	Clients    map[string][]string
	Handshakes map[string][]HandshakeFrame
}

func initDiscovery() Discovery {
	aps := make(map[string]AccessPoint)
	clients := make(map[string][]string)
	handshakes := make(map[string][]HandshakeFrame)
	return Discovery{
		APs:        aps,
		Clients:    clients,
		Handshakes: handshakes,
	}
}

func (d *Discovery) addClient(bssid, clientMAC string) {
	ap, ok := d.Clients[bssid]
	if ok {
		if !slices.Contains(ap, clientMAC) {
			d.Clients[bssid] = append(ap, clientMAC)
		}
	} else {
		d.Clients[bssid] = []string{clientMAC}
	}
}

func (d *Discovery) addHandshake(frame HandshakeFrame) {
	d.Handshakes[frame.BSSID] = append(d.Handshakes[frame.BSSID], frame)
}

func (d *Discovery) addAP(bssid, ssid string, channel int, security Dot11Security, signal int8, numPackets int) AccessPoint {
	if existing, ok := d.APs[bssid]; ok {
		// Use last captured signal strength
		existing.RSSI = signal

		if !slices.Contains(existing.Channels, channel) {
			existing.Channels = append(existing.Channels, channel)
		}

		// existing.SeenAt = ci.Timestamp.Unix()
		stats := existing.ChannelStats[channel]
		stats.numPackets = numPackets
		existing.ChannelStats[channel] = stats
		existing.Clients = getMapValue(d.Clients, bssid)

		d.APs[bssid] = existing

		return existing.deepCopy()
	} else {
		ap := AccessPoint{
			BSSID:        bssid,
			SSID:         ssid,
			Channels:     []int{channel},
			Clients:      getMapValue(d.Clients, bssid),
			RSSI:         signal,
			ChannelStats: map[int]channelStats{channel: {numPackets: numPackets}},
			Security:     fmt.Sprintf("%s %s %s", security.Encryption, security.Cipher, security.Auth),
			// SeenAt:       ci.Timestamp.Unix(),
		}

		d.APs[bssid] = ap

		return ap
	}
}

// AccessPoint represents a WiFi access point
type AccessPoint struct {
	BSSID        string               `json:"bssid"`
	SSID         string               `json:"ssid"`
	Channels     []int                `json:"channels"`
	ChannelStats map[int]channelStats `json:"channel_stats"`
	Clients      []string             `json:"client"`
	RSSI         int8                 `json:"rssi"`
	Security     string               `json:"security"`
	SeenAt       int64                `json:"seen_at"`
}

// deepCopy creates a deep copy of the AccessPoint
func (ap AccessPoint) deepCopy() AccessPoint {
	channels := make([]int, len(ap.Channels))
	copy(channels, ap.Channels)

	clients := make([]string, len(ap.Clients))
	copy(clients, ap.Clients)

	channelStats := make(map[int]channelStats)
	for k, v := range ap.ChannelStats {
		channelStats[k] = v
	}

	return AccessPoint{
		BSSID:        ap.BSSID,
		SSID:         ap.SSID,
		Channels:     channels,
		Clients:      clients,
		ChannelStats: channelStats,
		RSSI:         ap.RSSI,
		Security:     ap.Security,
		SeenAt:       ap.SeenAt,
	}
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

func getMapValue(m map[string][]string, v string) []string {
	val, ok := m[v]
	if ok {
		return val
	}
	return []string{}
}

// scanForAccessPoints scans for WiFi access points by capturing beacon/probe response frames
// This method can get actual BSSIDs even on modern macOS where airport utility is deprecated
// and Swift Core WiFi utils require geo location permission to see BSSIDs
// channels: list of channels to scan (e.g., []int{1,6,11} for 2.4GHz)
// scanTime: time to spend on each channel (e.g., 500ms)
// updateChan: channel to send real-time updates to the UI
// channelChan: channel to send current channel updates
// Returns a map of BSSID -> AccessPoint
func scanForAccessPoints(iface string, channels []int, scanTime time.Duration, verbose bool, updateCh chan<- APUpdateMsg, channelCh chan<- ChannelUpdateMsg, handshakeCh chan<- HandshakeUpdateMsg, errCh chan<- error) (map[string]AccessPoint, error) {
	d := initDiscovery()

	handle, err := pcap.OpenLive(iface, 65536, true, 100*time.Millisecond)
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
	// if err := handle.SetBPFFilter("type mgt subtype beacon"); err != nil {
	// 	return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	// }

	for _, channel := range channels {
		// fmt.Printf("\n[D] Setting chan: %d\n", channel)
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
		numPackets := 0
		for time.Now().Before(deadline) {
			data, _, err := handle.ReadPacketData()
			if err != nil {
				errCh <- fmt.Errorf("error reading packet on channel %d: %v", channel, err)
				continue
			}

			numPackets++

			packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)

			rTap := getRadioTapLayer(packet)
			if rTap == nil {
				continue
			}

			dot11 := getDot11Layer(packet)
			if dot11 == nil {
				continue
			}

			switch dot11.Type {
			case layers.Dot11TypeMgmtBeacon,
				layers.Dot11TypeMgmtProbeResp,
				layers.Dot11TypeMgmtProbeReq:

				// AP discovery frames

				signal := rTap.DBMAntennaSignal
				if rTap.DBMAntennaSignal == 0 {
					signal = -100
				}

				// Address3 is BSSID in beacon/probe frames
				bssid := dot11.Address3.String()

				ssid := extractSSIDFromBeacon(packet)
				_, security := dot11ParseEncryption(packet, dot11)

				ap := d.addAP(bssid, ssid, channel, security, signal, numPackets)

				if updateCh != nil {
					updateCh <- APUpdateMsg{BSSID: bssid, AP: ap}
				}

			case layers.Dot11TypeData:

				// Data frames can help discover clients associated with APs

				if dot11.Flags.ToDS() && !dot11.Flags.FromDS() {
					// Client to AP: Address1 = BSSID (receiver/AP), Address2 = Source (client)
					bssid := dot11.Address1.String()
					clientMAC := dot11.Address2.String()
					// fmt.Printf("[D] Client %s -> AP %s (ToDS)\n", clientMAC, bssid)
					d.addClient(bssid, clientMAC)
				} else if !dot11.Flags.ToDS() && dot11.Flags.FromDS() {
					// AP to Client: Address2 = BSSID (transmitter/AP), Address1 = Destination (client)
					bssid := dot11.Address2.String()
					clientMAC := dot11.Address1.String()
					// fmt.Printf("[D] AP %s -> Client %s (FromDS)\n", bssid, clientMAC)
					d.addClient(bssid, clientMAC)
				}

			case layers.Dot11TypeMgmtAssociationReq,
				layers.Dot11TypeMgmtAssociationResp,
				layers.Dot11TypeMgmtReassociationReq,
				layers.Dot11TypeMgmtReassociationResp:

				// Handshakes

				ok, msg := parseHandshakeFrame(packet)
				if !ok {
					continue
				}

				d.addHandshake(msg)
				if handshakeCh != nil {
					handshakeCh <- HandshakeUpdateMsg{BSSID: msg.BSSID, Frame: msg}
				}
			default:
				continue
			}

		}
	}

	return d.APs, nil
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

// isEAPOL checks if the packet contains an EAPOL layer (WPA handshake)
func isEAPOL(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeEAPOL) != nil
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
