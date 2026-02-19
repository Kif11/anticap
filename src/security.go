/* This is taken from bettercap tool https://github.com/bettercap/bettercap/blob/master/network/net_darwin.go */

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var wpaSignatureBytes = []byte{0, 0x50, 0xf2, 1}

type CipherSuite struct {
	OUI  []byte // 3 bytes
	Type Dot11CipherType
}

type AuthSuite struct {
	OUI  []byte // 3 bytes
	Type Dot11AuthType
}

type CipherSuiteSelector struct {
	Count  uint16
	Suites []CipherSuite
}

type AuthSuiteSelector struct {
	Count  uint16
	Suites []AuthSuite
}

type RSNInfo struct {
	Version  uint16
	Group    CipherSuite
	Pairwise CipherSuiteSelector
	AuthKey  AuthSuiteSelector
}

type VendorInfo struct {
	WPAVersion uint16
	Multicast  CipherSuite
	Unicast    CipherSuiteSelector
	AuthKey    AuthSuiteSelector
}

type Dot11AuthType uint8

func (a Dot11AuthType) String() string {
	// https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-ieee80211.c
	switch a {
	case 0:
		return "NONE"
	case 1:
		return "WPA"
	case 2:
		return "PSK"
	case 3:
		return "FT over IEEE 802.1X"
	case 4:
		return "FT using PSK"
	case 5:
		return "WPA (SHA256)"
	case 6:
		return "PSK (SHA256)"
	case 7:
		return "TDLS / TPK Handshake (SHA256)"
	case 8:
		return "SAE (SHA256)"
	case 9:
		return "FT using SAE (SHA256)"
	case 10:
		return "APPeerKey (SHA256)"
	case 11:
		return "WPA (SHA256-SuiteB)"
	case 12:
		return "WPA (SHA384-SuiteB)"
	case 13:
		return "FT over IEEE 802.1X (SHA384)"
	case 14:
		return "FILS (SHA256 and AES-SIV-256)"
	case 15:
		return "FILS (SHA384 and AES-SIV-512)"
	case 16:
		return "FT over FILS (SHA256 and AES-SIV-256)"
	case 17:
		return "FT over FILS (SHA384 and AES-SIV-512)"
	case 18:
		return "Opportunistic Wireless Encryption"
	case 19:
		return "FT using PSK (SHA384)"
	case 20:
		return "PSK (SHA384)"
	case 21:
		return "PASN"
	case 24:
		return "SAE (GROUP-DEPEND)"
	case 25:
		return "FT using SAE (GROUP-DEPEND)"
	default:
		return fmt.Sprintf("AUTH %d", a)
	}
}

type Dot11CipherType uint8

func (a Dot11CipherType) String() string {
	switch a {
	case 0:
		return "NONE"
	case 1:
		return "WEP-40-bit"
	case 2:
		return "TKIP"
	case 3:
		return "AES-OCB"
	case 4:
		return "AES-CCM"
	case 5:
		return "WEP-104-bit"
	case 6:
		return "BIP-128"
	case 7:
		return "Group addressed traffic not allowed"
	case 8:
		return "GCMP-128"
	case 9:
		return "GCMP-256"
	case 10:
		return "CCMP-256"
	case 11:
		return "BIP-GMAC-128"
	case 12:
		return "BIP-GMAC-256"
	case 13:
		return "BIP-CMAC-256"
	default:
		return fmt.Sprintf("CIPHER %d", a)
	}
}

type Dot11Security struct {
	Encryption string
	Cipher     string
	Auth       string
}

func dot11ParseEncryption(packet gopacket.Packet, dot11 *layers.Dot11) (bool, Dot11Security) {
	var i uint16
	enc := ""
	cipher := ""
	auth := ""
	found := false

	if dot11.Flags.WEP() {
		found = true
		enc = "WEP"
	}

	for _, layer := range packet.Layers() {
		if layer.LayerType() == layers.LayerTypeDot11InformationElement {
			info, ok := layer.(*layers.Dot11InformationElement)
			if ok {
				found = true
				if info.ID == layers.Dot11InformationElementIDRSNInfo {
					enc = "WPA2"
					rsn, err := dot11InformationElementRSNInfoDecode(info.Info)
					if err == nil {
						for i = 0; i < rsn.Pairwise.Count; i++ {
							cipher = rsn.Pairwise.Suites[i].Type.String()
						}
						for i = 0; i < rsn.AuthKey.Count; i++ {
							// https://balramdot11b.com/2020/11/08/wpa3-deep-dive/
							if rsn.AuthKey.Suites[i].Type == 8 {
								auth = "SAE"
								enc = "WPA3"
							} else {
								auth = rsn.AuthKey.Suites[i].Type.String()
							}
						}
					}
				} else if enc == "" && info.ID == layers.Dot11InformationElementIDVendor && info.Length >= 8 && bytes.Equal(info.OUI, wpaSignatureBytes) && bytes.HasPrefix(info.Info, []byte{1, 0}) {
					enc = "WPA"
					vendor, err := dot11InformationElementVendorInfoDecode(info.Info)
					if err == nil {
						for i = 0; i < vendor.Unicast.Count; i++ {
							cipher = vendor.Unicast.Suites[i].Type.String()
						}
						for i = 0; i < vendor.AuthKey.Count; i++ {
							auth = vendor.AuthKey.Suites[i].Type.String()
						}
					}
				}
			}
		}
	}

	if found && enc == "" {
		enc = "OPEN"
	}

	return found, Dot11Security{enc, cipher, auth}
}

func dot11InformationElementVendorInfoDecode(buf []byte) (v VendorInfo, err error) {
	if err = canParse("Vendor", buf, 8); err == nil {
		v.WPAVersion = binary.LittleEndian.Uint16(buf[0:2])
		v.Multicast.OUI = buf[2:5]
		v.Multicast.Type = Dot11CipherType(buf[5])
		v.Unicast.Count = binary.LittleEndian.Uint16(buf[6:8])
		buf = buf[8:]
	} else {
		v.Unicast.Count = 0
		return
	}

	// check what we're left with
	if err = canParse("Vendor.Unicast.Suites", buf, int(v.Unicast.Count)*4); err == nil {
		for i := uint16(0); i < v.Unicast.Count; i++ {
			if suite, err := parsePairwiseSuite(buf); err == nil {
				v.Unicast.Suites = append(v.Unicast.Suites, suite)
				buf = buf[4:]
			} else {
				return v, err
			}
		}
	} else {
		v.Unicast.Count = 0
		return
	}

	if err = canParse("Vendor.AuthKey.Count", buf, 2); err == nil {
		v.AuthKey.Count = binary.LittleEndian.Uint16(buf[0:2])
		buf = buf[2:]
	} else {
		v.AuthKey.Count = 0
		return
	}

	// just like before, check if we have enough data
	if err = canParse("Vendor.AuthKey.Suites", buf, int(v.AuthKey.Count)*4); err == nil {
		for i := uint16(0); i < v.AuthKey.Count; i++ {
			if suite, err := parseAuthkeySuite(buf); err == nil {
				v.AuthKey.Suites = append(v.AuthKey.Suites, suite)
				buf = buf[4:]
			} else {
				return v, err
			}
		}
	} else {
		v.AuthKey.Count = 0
	}

	return
}

func canParse(what string, buf []byte, need int) error {
	available := len(buf)
	if need > available {
		return fmt.Errorf("Malformed 802.11 packet, could not parse %s: needed %d bytes but only %d are available.", what, need, available)
	}
	return nil
}

func parsePairwiseSuite(buf []byte) (suite CipherSuite, err error) {
	if err = canParse("RSN.Pairwise.Suite", buf, 4); err == nil {
		suite.OUI = buf[0:3]
		suite.Type = Dot11CipherType(buf[3])
	}
	return
}

func parseAuthkeySuite(buf []byte) (suite AuthSuite, err error) {
	if err = canParse("RSN.AuthKey.Suite", buf, 4); err == nil {
		suite.OUI = buf[0:3]
		suite.Type = Dot11AuthType(buf[3])
	}
	return
}

func dot11InformationElementRSNInfoDecode(buf []byte) (rsn RSNInfo, err error) {
	if err = canParse("RSN", buf, 8); err == nil {
		rsn.Version = binary.LittleEndian.Uint16(buf[0:2])
		rsn.Group.OUI = buf[2:5]
		rsn.Group.Type = Dot11CipherType(buf[5])
		rsn.Pairwise.Count = binary.LittleEndian.Uint16(buf[6:8])
		buf = buf[8:]
	} else {
		rsn.Pairwise.Count = 0
		return
	}

	// check what we're left with
	if err = canParse("RSN.Pairwise.Suites", buf, int(rsn.Pairwise.Count)*4); err == nil {
		for i := uint16(0); i < rsn.Pairwise.Count; i++ {
			if suite, err := parsePairwiseSuite(buf); err == nil {
				rsn.Pairwise.Suites = append(rsn.Pairwise.Suites, suite)
				buf = buf[4:]
			} else {
				return rsn, err
			}
		}
	} else {
		rsn.Pairwise.Count = 0
		return
	}

	if err = canParse("RSN.AuthKey.Count", buf, 2); err == nil {
		rsn.AuthKey.Count = binary.LittleEndian.Uint16(buf[0:2])
		buf = buf[2:]
	} else {
		rsn.AuthKey.Count = 0
		return
	}

	// just like before, check if we have enough data
	if err = canParse("RSN.AuthKey.Suites", buf, int(rsn.AuthKey.Count)*4); err == nil {
		for i := uint16(0); i < rsn.AuthKey.Count; i++ {
			if suite, err := parseAuthkeySuite(buf); err == nil {
				rsn.AuthKey.Suites = append(rsn.AuthKey.Suites, suite)
				buf = buf[4:]
			} else {
				return rsn, err
			}
		}
	} else {
		rsn.AuthKey.Count = 0
	}

	return
}

// Returns a numeric value for security strength (lower = weaker)
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
