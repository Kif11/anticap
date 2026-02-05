package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// HandshakeFrame represents a captured handshake message
type HandshakeFrame struct {
	Num       int // 1-4 for the 4-way handshake
	BSSID     string
	ClientMAC string
	Timestamp time.Time
}

// Identifies which message of the 4-way handshake this is
func identifyHandshakeMessage(k *layers.EAPOLKey) int {
	// Message 1: AP -> STA
	// - KeyType = Pairwise (true)
	// - KeyACK = true
	// - KeyMIC = false
	// - Secure = false
	// - Nonce = ANonce
	if k.KeyACK && !k.KeyMIC && !k.Secure {
		return 1
	}

	// Message 2: STA -> AP
	// - KeyType = Pairwise (true)
	// - KeyACK = false
	// - KeyMIC = true
	// - Secure = false
	// - Nonce = SNonce
	if !k.KeyACK && k.KeyMIC && !k.Secure {
		return 2
	}

	// Message 3: AP -> STA
	// - KeyType = Pairwise (true)
	// - KeyACK = true
	// - KeyMIC = true
	// - Secure = true
	// - Contains GTK in KeyData
	if k.KeyACK && k.KeyMIC && k.Secure {
		return 3
	}

	// Message 4: STA -> AP
	// - KeyType = Pairwise (true)
	// - KeyACK = false
	// - KeyMIC = true
	// - Secure = true
	// - No KeyData
	if !k.KeyACK && k.KeyMIC && k.Secure {
		return 4
	}

	return 0 // Unknown
}

func getClientMAC(dot11 *layers.Dot11) string {
	if dot11.Flags.FromDS() {
		return dot11.Address2.String()
	}
	if dot11.Flags.ToDS() {
		return dot11.Address1.String()
	}
	// NOTE (kif): There are two other possibilities
	// fromDC=0 and toDC=0 - Frame is sent directly between two stations
	// fromDC=1 and toDC=1 - Frame send between two DC (mesh network)
	// For now we just return first address
	return dot11.Address1.String()
}

// Processes a packet and checks if it's part of a 4-way handshake
func parseHandshakeFrame(packet gopacket.Packet, bssid string, verbose bool) (HandshakeFrame, error) {
	// Normalize BSSID to lowercase for comparison
	bssid = strings.ToLower(bssid)

	// Get Dot11 layer
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return HandshakeFrame{}, fmt.Errorf("can not get Dot11 layer")
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return HandshakeFrame{}, fmt.Errorf("can not cast layer to Dot11")
	}

	// Get EAPOL layer
	eapolLayer := packet.Layer(layers.LayerTypeEAPOL)
	if eapolLayer == nil {
		return HandshakeFrame{}, fmt.Errorf("can not get EAPOL layer")
	}

	// if verbose {
	// 	fmt.Printf("[DEBUG] Found EAPOL packet! Addr1=%s Addr2=%s Addr3=%s, FromDS: %t, ToDS: %t\n",
	// 		dot11.Address1.String(), dot11.Address2.String(), dot11.Address3.String(), dot11.Flags.FromDS(), dot11.Flags.ToDS())
	// }
	eapol, ok := eapolLayer.(*layers.EAPOL)
	if !ok || eapol.Type != layers.EAPOLTypeKey {
		return HandshakeFrame{}, fmt.Errorf("can not cast layer to layers.EAPOL or not a Key frame")
	}

	var key *layers.EAPOLKey
	if eapol.Type == layers.EAPOLTypeKey {
		if keyLayer := packet.Layer(layers.LayerTypeEAPOLKey); keyLayer != nil {
			key = keyLayer.(*layers.EAPOLKey)

			// fmt.Printf("  → EAPOL-Key frame\n")
			// fmt.Printf("    Descriptor:   %v\n", key.KeyDescriptorType)
			// fmt.Printf("    Key Type:     %v\n", key.KeyType) // Pairwise / Group
			// fmt.Printf("    Key ACK:      %v\n", key.KeyACK)
			// fmt.Printf("    Key MIC:      %v\n", key.KeyMIC)
			// fmt.Printf("    Secure:       %v\n", key.Secure)
			// fmt.Printf("    Request:      %v\n", key.Request)
			// fmt.Printf("    Encrypted Key Data: %v\n", key.EncryptedKeyData)
		} else {
			return HandshakeFrame{}, fmt.Errorf("can not parse EAPOL Key layer")
		}
	}

	// Identify which message this is
	msgNum := identifyHandshakeMessage(key)
	if msgNum == 0 {
		return HandshakeFrame{}, fmt.Errorf("not a recognized handshake message")
	}

	// Store the message
	msg := HandshakeFrame{
		Num:       msgNum, //TODO
		BSSID:     dot11.Address3.String(),
		ClientMAC: getClientMAC(dot11),
		Timestamp: time.Now(),
	}

	return msg, nil
}

// CaptureHandshake captures 4-way handshake packets for a specific BSSID
func captureHandshake(iface string, bssid string, channel int, timeout time.Duration, outputFile string, verbose bool) error {
	if verbose {
		fmt.Printf("Starting handshake capture for BSSID: %s on channel %d\n", bssid, channel)
		fmt.Printf("Output file: %s\n", outputFile)
		fmt.Printf("Timeout: %v\n", timeout)
	}

	// Set channel
	if err := setChannel(iface, channel); err != nil {
		return fmt.Errorf("failed to set channel: %w", err)
	}

	var f *os.File
	var pcapWriter *pcapgo.Writer

	if outputFile != "" {
		// Create output directory if it doesn't exist
		dir := filepath.Dir(outputFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		// Open output file in append mode
		var err error
		f, err = os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer f.Close()

		// Check if file is empty (new file) to write pcap header
		fileInfo, err := f.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat output file: %w", err)
		}

		// Initialize pcap writer
		pcapWriter = pcapgo.NewWriter(f)

		// Write pcap header only if file is new/empty
		if fileInfo.Size() == 0 {
			if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeIEEE80211Radio); err != nil {
				return fmt.Errorf("failed to write pcap header: %w", err)
			}
		}
	}

	// Open pcap handle with a short timeout so we can check the deadline
	handle, err := pcap.OpenLive(iface, 65536, true, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("failed to open interface: %w", err)
	}
	defer handle.Close()

	// Set to capture IEEE802.11 radio packets
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		return fmt.Errorf("failed to set link type: %w", err)
	}

	// Set BPF filter to capture only EAPOL and beacon frames
	bpfFilter := fmt.Sprintf("wlan host %s and (wlan proto 0x888e or wlan type mgt subtype beacon)", bssid)
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}
	if verbose {
		fmt.Printf("Applied BPF filter: %s\n", bpfFilter)
	}

	fmt.Printf("\n[*] Waiting for 4-way handshake...\n")
	fmt.Printf("[*] Try to connect a device to the network to trigger the handshake\n\n")

	// Use ReadPacketData directly for more reliable packet capture
	deadline := time.Now().Add(timeout)
	packetCount := 0
	for time.Now().Before(deadline) {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if verbose {
				fmt.Printf("Warning: error reading packet: %v\n", err)
			}
			continue
		}

		packetCount++
		// if verbose && packetCount%100 == 0 {
		// 	fmt.Printf("[*] Received %d packets so far...\n", packetCount)
		// }
		// Write packet to pcap file
		if pcapWriter != nil {
			if err := pcapWriter.WritePacket(ci, data); err != nil {
				if verbose {
					fmt.Printf("Warning: failed to write packet: %v\n", err)
				}
			}
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)

		msg, err := parseHandshakeFrame(packet, bssid, verbose)
		if err != nil {
			continue
		}

		fmt.Printf("[+] %d, BSSID: %s, CLIENT: %s\n", msg.Num, msg.BSSID, msg.ClientMAC)
	}

	return nil
}
