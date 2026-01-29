package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"

	scribble "github.com/nanobox-io/golang-scribble"
)

// Structs for parsing system_profiler JSON output
type NetworkInfo struct {
	Name         string `json:"_name"`
	Channel      string `json:"spairport_network_channel"`
	PhyMode      string `json:"spairport_network_phymode"`
	Type         string `json:"spairport_network_type"`
	SecurityMode string `json:"spairport_security_mode"`
	SignalNoise  string `json:"spairport_signal_noise"`
	CountryCode  string `json:"spairport_network_country_code,omitempty"`
	MCS          int    `json:"spairport_network_mcs,omitempty"`
	Rate         int    `json:"spairport_network_rate,omitempty"`
}

type AirPortInterface struct {
	Name                    string        `json:"_name"`
	MACAddress              string        `json:"spairport_wireless_mac_address"`
	OtherLocalNetworks      []NetworkInfo `json:"spairport_airport_other_local_wireless_networks,omitempty"`
	CapsAirdrop             string        `json:"spairport_caps_airdrop,omitempty"`
	CapsAutoUnlock          string        `json:"spairport_caps_autounlock,omitempty"`
	CapsWOW                 string        `json:"spairport_caps_wow,omitempty"`
	CurrentNetworkInfo      NetworkInfo   `json:"spairport_current_network_information,omitempty"`
	StatusInfo              string        `json:"spairport_status_information,omitempty"`
	SupportedChannels       []string      `json:"spairport_supported_channels,omitempty"`
	SupportedPhyModes       string        `json:"spairport_supported_phymodes,omitempty"`
	WirelessCardType        string        `json:"spairport_wireless_card_type,omitempty"`
	WirelessCountryCode     string        `json:"spairport_wireless_country_code,omitempty"`
	WirelessFirmwareVersion string        `json:"spairport_wireless_firmware_version,omitempty"`
	WirelessLocale          string        `json:"spairport_wireless_locale,omitempty"`
}

type SoftwareInformation struct {
	CoreWLANVersion    string `json:"spairport_corewlan_version"`
	CoreWLANKitVersion string `json:"spairport_corewlankit_version"`
	DiagnosticsVersion string `json:"spairport_diagnostics_version"`
	ExtraVersion       string `json:"spairport_extra_version"`
	FamilyVersion      string `json:"spairport_family_version"`
	ProfilerVersion    string `json:"spairport_profiler_version"`
	UtilityVersion     string `json:"spairport_utility_version"`
}

type AirPortDataType struct {
	Interfaces          []AirPortInterface  `json:"spairport_airport_interfaces"`
	SoftwareInformation SoftwareInformation `json:"spairport_software_information"`
}

type SystemProfilerResponse struct {
	SPAirPortDataType []AirPortDataType `json:"SPAirPortDataType"`
}

// Structs for CoreWLAN-based WiFi scan (includes BSSIDs)
type ScannedNetwork struct {
	SSID     string `json:"ssid"`
	BSSID    string `json:"bssid"`
	Channel  int    `json:"channel"`
	Band     string `json:"band"`
	RSSI     int    `json:"rssi"`
	Noise    int    `json:"noise"`
	Security string `json:"security"`
}

type WifiScanResult struct {
	Success   bool             `json:"success"`
	Error     string           `json:"error,omitempty"`
	Interface string           `json:"interface,omitempty"`
	Networks  []ScannedNetwork `json:"networks"`
}

// AssociateResult represents the result of a WiFi association attempt
type AssociateResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	SSID    string `json:"ssid,omitempty"`
	BSSID   string `json:"bssid,omitempty"`
}

//go:embed swift/dissociate_wifi.swift
var dissociateWiFiSwift string

//go:embed swift/set_channel.swift
var setChannelSwift string

//go:embed swift/associate_wifi.swift
var associateWiFiSwift string

// runSwift executes a Swift script with the given code.
func runSwift(code string, args ...string) ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "*.swift")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(code)
	if err != nil {
		return nil, err
	}

	cmdArgs := []string{tmpFile.Name()}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("swift", cmdArgs...)
	return cmd.Output()
}

func getMac(interfc string) (string, error) {
	netInterface, err := net.InterfaceByName(interfc)
	if err != nil {
		return "", err
	}
	return netInterface.HardwareAddr.String(), nil
}

func repairMac(mac string) string {
	parts := strings.Split(mac, ":")

	var newParts []string

	for _, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		newParts = append(newParts, p)
	}

	return strings.Join(newParts, ":")
}

func listWifiNetworks() ([]NetworkInfo, error) {
	spResponse, err := systemProfileAirportInfo()
	if err != nil {
		return nil, err
	}

	if len(spResponse.SPAirPortDataType) == 0 {
		return nil, fmt.Errorf("no AirPort data found in system profiler output")
	}

	airportData := spResponse.SPAirPortDataType[0]
	if len(airportData.Interfaces) == 0 {
		return nil, fmt.Errorf("no AirPort interfaces found in system profiler output")
	}

	var networks []NetworkInfo
	for _, iface := range airportData.Interfaces {
		networks = append(networks, iface.OtherLocalNetworks...)
	}

	return networks, nil
}

func systemProfileAirportInfo() (*SystemProfilerResponse, error) {
	output, err := exec.Command("system_profiler", "-json", "SPAirPortDataType").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get system profiler data: %w", err)
	}

	var spResponse SystemProfilerResponse
	if err := json.Unmarshal(output, &spResponse); err != nil {
		return nil, fmt.Errorf("failed to parse system profiler JSON: %w", err)
	}

	return &spResponse, nil
}

func getRouterAddress() (string, error) {
	// Get the default gateway IP and then look up its MAC address in ARP table
	cmd := exec.Command("sh", "-c", "arp -n $(route get default | grep gateway | awk '{print $2}')")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get router MAC address: %w", err)
	}

	// Parse the ARP output to extract MAC address
	// Expected format: "? (192.168.1.1) at 8c:dc:2:7a:a7:17 on en0 ifscope [ethernet]"
	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return "", fmt.Errorf("no ARP entry found for default gateway")
	}

	// Split by spaces and find the MAC address (format: xx:xx:xx:xx:xx:xx)
	parts := strings.Fields(outputStr)
	for _, part := range parts {
		if strings.Contains(part, ":") && len(strings.Split(part, ":")) == 6 {
			return repairMac(part), nil
		}
	}

	return "", fmt.Errorf("no MAC address found in ARP output: %s", outputStr)
}

func dissociateWiFi() error {
	_, err := runSwift(dissociateWiFiSwift)
	if err != nil {
		return fmt.Errorf("failed to disassociate WiFi: %w", err)
	}

	return nil
}

// associateWiFi connects to a WiFi network by its SSID
// ssid: the network name to connect to
// password: the network password (empty string for open networks)
func associateWiFi(ssid string, password string) (AssociateResult, error) {
	var output []byte
	var err error

	if password == "" {
		output, err = runSwift(associateWiFiSwift, ssid)
	} else {
		output, err = runSwift(associateWiFiSwift, ssid, password)
	}

	if err != nil {
		// Try to parse JSON error from output
		var result AssociateResult
		if jsonErr := json.Unmarshal(output, &result); jsonErr == nil {
			return result, fmt.Errorf("association failed: %s", result.Error)
		}
		return AssociateResult{}, fmt.Errorf("failed to associate with WiFi: %w", err)
	}

	var result AssociateResult
	if err := json.Unmarshal(output, &result); err != nil {
		return AssociateResult{}, fmt.Errorf("failed to parse association result: %w", err)
	}

	if !result.Success {
		return result, fmt.Errorf("association failed: %s", result.Error)
	}

	return result, nil
}

func setMac(interfc string, mac string) error {
	if err := dissociateWiFi(); err != nil {
		return err
	}

	// Spoof mac
	if err := exec.Command("ifconfig", interfc, "ether", mac).Run(); err != nil {
		return err
	}

	// Detect new network hardware and create a default network service on the hardware
	if err := exec.Command("networksetup", "-detectnewhardware").Run(); err != nil {
		return err
	}

	// Restart WiFi interface to connect back
	if err := exec.Command("networksetup", "-setairportpower", interfc, "off").Run(); err != nil {
		return err
	}
	if err := exec.Command("networksetup", "-setairportpower", interfc, "on").Run(); err != nil {
		return err
	}

	return nil
}

func isSudo() bool {
	if os.Getenv("SUDO_USER") != "" {
		return true
	}
	return false
}

func resetOriginalMac(db *scribble.Driver, interfc string) error {
	i := networkInterface{}
	if err := db.Read("interfaces", interfc, &i); err != nil {
		return err
	}
	if *verbose {
		fmt.Printf("Resseting mac address to %s for %s\n", i.Address, interfc)
	}

	setMac(interfc, i.Address)

	return nil
}

func sortDevices(devices map[string]device) []device {
	var deviceArray []device
	for _, d := range devices {
		deviceArray = append(deviceArray, d)
	}

	sort.SliceStable(deviceArray, func(i, j int) bool {
		return deviceArray[i].PCount > deviceArray[j].PCount
	})

	return deviceArray
}
