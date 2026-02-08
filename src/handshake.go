package main

import (
	"fmt"
	"os"
	"path/filepath"
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
func parseHandshakeFrame(packet gopacket.Packet) (bool, HandshakeFrame) {
	// Get Dot11 layer
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return false, HandshakeFrame{}
	}
	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return false, HandshakeFrame{}
	}

	// Get EAPOLKey layer
	keyLayer := packet.Layer(layers.LayerTypeEAPOLKey)
	if keyLayer == nil {
		return false, HandshakeFrame{}
	}
	EAPOLKey, ok := keyLayer.(*layers.EAPOLKey)
	if !ok {
		return false, HandshakeFrame{}
	}

	msgNum := identifyHandshakeMessage(EAPOLKey)
	if msgNum == 0 {
		fmt.Println("Warning! can not identify hand shake message type.")
		return false, HandshakeFrame{}
	}

	msg := HandshakeFrame{
		Num:       msgNum,
		BSSID:     dot11.Address3.String(), // Address3 should be always BSSID
		ClientMAC: getClientMAC(dot11),
		Timestamp: time.Now(),
	}

	return true, msg
}

// CaptureHandshake captures 4-way handshake packets for a specific BSSID
func captureHandshake(iface string, bssid string, channel int, outputFile string, verbose bool) error {
	if verbose {
		fmt.Printf("Starting handshake capture for BSSID: %s on channel %d\n", bssid, channel)
		fmt.Printf("Output file: %s\n", outputFile)
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
	handle, err := pcap.OpenLive(iface, 65536, true, 1*time.Second)
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
		fmt.Printf("Using BPF filter: %s\n", bpfFilter)
	}

	fmt.Printf("Waiting for 4-way handshake...\n")
	fmt.Printf("Wait for a device to connect to the network to trigger the handshake\n\n")

	// Use ReadPacketData directly for more reliable packet capture
	packetCount := 0
	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			fmt.Printf("Warning: error reading packet: %v\n", err)
			continue
		}

		packetCount++

		if verbose {
			if packetCount%100 == 0 {
				fmt.Printf("Captured %d packets\n", packetCount)
			}
		}

		// Write packet to pcap file
		if pcapWriter != nil {
			if err := pcapWriter.WritePacket(ci, data); err != nil {
				if verbose {
					fmt.Printf("Warning: failed to write packet: %v\n", err)
				}
			}
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)

		ok, msg := parseHandshakeFrame(packet)
		if !ok {
			continue
		}

		fmt.Printf("[+] %d, BSSID: %s, CLIENT: %s\n", msg.Num, msg.BSSID, msg.ClientMAC)
	}
}
