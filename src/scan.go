package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const maxDuration time.Duration = 1<<63 - 1

type channelStats struct {
	numPackets int
}

// PacketInfo holds extracted information from a single packet
type PacketInfo struct {
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

func scan(
	iface string,
	channels []int,
	scanTime time.Duration,
	outFile string,
	updateCh chan<- APUpdateMsg,
	clientUpdateCh chan<- ClientUpdateMsg,
	channelCh chan<- ChannelUpdateMsg,
	handshakeCh chan<- HandshakeUpdateMsg,
	errCh chan<- error) error {

	handle, err := pcap.OpenLive(iface, 65536, true, 100*time.Millisecond)
	if err != nil {
		return nil
	}
	defer handle.Close()

	// Set to capture IEEE802.11 radio packets (Monitor Mode)
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		return nil
	}

	ps := PacketStore{}
	err = ps.Init(outFile)
	if err != nil {
		return err
	}
	defer ps.Close()

	i := 0
	for {
		// Loop continuously through available channels
		if i > len(channels)-1 {
			i = 0
		}

		channel := channels[i]

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

		// When using one channel keep listening on it forever
		if len(channels) == 1 {
			deadline = time.Now().Add(maxDuration)
		}

		numPackets := 0
		for time.Now().Before(deadline) {
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				errCh <- fmt.Errorf("error reading packet on channel %d: %v", channel, err)
				continue
			}

			// Save packet to a file
			err = ps.Write(ci, data)
			if err != nil {
				return nil
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

			if keyLayer := packet.Layer(layers.LayerTypeEAPOLKey); keyLayer != nil {
				ok, msg := parseHandshakeFrame(keyLayer, dot11)
				if !ok {
					continue
				}

				if handshakeCh != nil {
					handshakeCh <- HandshakeUpdateMsg{BSSID: msg.BSSID, Frame: msg}
				}

				// We don't use EAPOL message for client or AP discovery
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

				// Skip broadcast Probe Request frames
				// Clients send those frames to actively discover AP in the area
				// Those frames contains:
				//     Source MAC (Address2): The client device's MAC address
				//     SSID: Either empty (wildcard scan for any network) or specific SSID(s) the client is looking for
				//     Supported Rates: Data rates the client supports
				//     Capabilities: HT/VHT capabilities (802.11n/ac/ax support)
				//     Vendor-specific IEs: Sometimes reveals device manufacturer/type
				// TODO: Implement client discovery and tagging in addition to AP discovery
				if dot11.Address3.String() == "ff:ff:ff:ff:ff:ff" {
					continue
				}

				// Address3 is BSSID in beacon/probe frames
				bssid := dot11.Address3.String()

				ssid := extractSSIDFromBeacon(packet)
				_, security := dot11ParseEncryption(packet, dot11)

				if updateCh != nil {
					updateCh <- APUpdateMsg{
						BSSID:      bssid,
						SSID:       ssid,
						Channel:    channel,
						Security:   security,
						Signal:     int(signal),
						NumPackets: numPackets,
					}
				}

			case layers.Dot11TypeData:

				// Data frames can help discover clients associated with APs
				// which helps to identify AP of interest

				clientMAC, bssid := getAddresses(dot11)

				if clientUpdateCh != nil {
					clientUpdateCh <- ClientUpdateMsg{BSSID: bssid, ClientMAC: clientMAC}
				}

			default:
				continue
			}
		}
		i++
	}
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
