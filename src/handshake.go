package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Captured handshake message
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

func getAddresses(dot11 *layers.Dot11) (client, ap string) {
	if dot11.Flags.FromDS() {
		return dot11.Address2.String(), dot11.Address1.String()
	}
	if dot11.Flags.ToDS() {
		return dot11.Address1.String(), dot11.Address2.String()
	}
	// NOTE (kif): There are two other possibilities
	// fromDC=0 and toDC=0 - Frame is sent directly between two stations
	// fromDC=1 and toDC=1 - Frame send between two DC (mesh network)
	// For now we just return first and second addresses as is
	return dot11.Address1.String(), dot11.Address2.String()
}

// Processes a packet and checks if it's part of a 4-way handshake
func parseHandshakeFrame(layer gopacket.Layer, dot11 *layers.Dot11) (bool, HandshakeFrame) {
	EAPOLKey, ok := layer.(*layers.EAPOLKey)
	if !ok {
		return false, HandshakeFrame{}
	}

	msgNum := identifyHandshakeMessage(EAPOLKey)
	if msgNum == 0 {
		fmt.Println("Warning! can not identify hand shake message type.")
		return false, HandshakeFrame{}
	}

	clientMac, _ := getAddresses(dot11)

	msg := HandshakeFrame{
		Num:       msgNum,
		BSSID:     dot11.Address3.String(), // Address3 should be always BSSID
		ClientMAC: clientMac,
		Timestamp: time.Now(),
	}

	return true, msg
}
