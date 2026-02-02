package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	scribble "github.com/nanobox-io/golang-scribble"
)

type device struct {
	Address        string `json:"address"`
	PCount         int    `json:"pcount"` // Total packet count
	Rating         int    `json:"rating"`
	AvgRSSI        int8   `json:"avg_rssi"`         // Average signal strength
	LastRSSI       int8   `json:"last_rssi"`        // Most recent reading
	LastSeen       int64  `json:"last_seen"`        // Unix timestamp
	RetryCount     int    `json:"retry_count"`      // Frames with Retry flag set
	DataFrameCount int    `json:"data_frame_count"` // Data frames (vs mgmt/ctrl)
	MaxDataRate    uint8  `json:"max_data_rate"`    // Highest observed rate
	SNR            int8   `json:"snr"`              // Signal-to-noise ratio
}

type networkInterface struct {
	Name    string
	Address string
}

// CachedNetwork represents cached network information
type CachedNetwork struct {
	BSSID   string `json:"bssid"`
	SSID    string `json:"ssid"`
	Channel int    `json:"channel"`
}

// Common 2.4GHz and 5GHz channels
var defaultChannels2G = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
var defaultChannels5G = []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}

var defaultTarget, _ = getRouterAddress()

func printUsage() {
	fmt.Println(`anticap - Captive portal bypass and WiFi network analysis tool

Usage:
  anticap <command> [options]

Commands:
  bypass    Run full bypass routine: packet capture, mac spoof, and internet connection testing
  scan      Scan for available WiFi networks
  capture   Run packet capture only (monitor mode)
  join      Connect to a WiFi network by name
  reset     Reset to original MAC address
  setmac    Set interface MAC address
  list      List stored captures for target MAC

Use "anticap <command> -h" for more information about a command.`)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	dir := "./store"
	db, err := scribble.New(dir, nil)
	if err != nil {
		fmt.Println("Error", err)
		return
	}

	switch os.Args[1] {
	case "bypass":
		if needsRoot(os.Args[2:]) {
			requireRoot()
		}
		cmdBypass(db)
	case "scan":
		if needsRoot(os.Args[2:]) {
			requireRoot()
		}
		cmdScan()
	case "capture":
		if needsRoot(os.Args[2:]) {
			requireRoot()
		}
		cmdCapture(db)
	case "join":
		if needsRoot(os.Args[2:]) {
			requireRoot()
		}
		cmdJoin()
	case "reset":
		if needsRoot(os.Args[2:]) {
			requireRoot()
		}
		cmdReset(db)
	case "setmac":
		if needsRoot(os.Args[2:]) {
			requireRoot()
		}
		cmdSetMac()
	case "list":
		cmdList(db)
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func requireRoot() {
	if !isSudo() {
		fmt.Println("This command must be run as root")
		os.Exit(1)
	}
}

func needsRoot(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "help" {
			return false
		}
	}
	return true
}

// cmdBypass runs the full process: packet capture, mac spoof, and connection testing
func cmdBypass(db *scribble.Driver) {
	bypassCmd := flag.NewFlagSet("bypass", flag.ExitOnError)
	targetInterface := bypassCmd.String("i", "en0", "name of wifi interface")
	targetDevice := bypassCmd.String("t", defaultTarget, "MAC address of target wifi network")
	targetChannel := bypassCmd.Int("ch", 0, "target radio channel (1-14)")
	maxNumPackets := bypassCmd.Int("n", 300, "number of packets to capture")
	manualSSID := bypassCmd.String("s", "", "manual SSID override (bypasses automatic resolution)")
	verbose := bypassCmd.Bool("v", false, "output more information")

	bypassCmd.Parse(os.Args[2:])

	if *targetDevice == "" {
		fmt.Println("Your are not associated with any WiFi networks at the moment therefor you must specify target network MAC with -t <MAC>.")
		fmt.Println("Use `anticap scan` to determine target MAC address.")
		os.Exit(1)
	}

	interfaceStore := fmt.Sprintf("store/interfaces/%s.json", *targetInterface)

	if _, err := os.Stat(interfaceStore); os.IsNotExist(err) {
		currentMacAddress, err := getMac(*targetInterface)
		if err != nil {
			log.Fatal(err)
		}

		if *verbose {
			fmt.Printf("Saving current mac address %s to %s\n", currentMacAddress, interfaceStore)
		}

		currentInterface := networkInterface{
			Name:    *targetInterface,
			Address: currentMacAddress,
		}

		db.Write("interfaces", *targetInterface, currentInterface)
	}

	// Resolve SSID from BSSID
	var ssid string
	if *manualSSID != "" {
		// Manual override provided
		ssid = *manualSSID
		if *verbose {
			fmt.Printf("Using manual SSID override: %s\n", ssid)
		}
	} else {
		// Try to resolve SSID automatically
		resolvedSSID, err := resolveSSIDFromBSSID(*targetDevice, *targetInterface, *verbose)
		if err != nil {
			fmt.Printf("Failed to resolve SSID for BSSID %s: %v\n", *targetDevice, err)
			fmt.Printf("\nSuggestions:\n")
			fmt.Printf("  1. Use manual SSID override: anticap bypass -t %s -s \"YourNetworkName\"\n", *targetDevice)
			fmt.Printf("  2. Run 'anticap scan' to populate the network cache\n")
			os.Exit(1)
		}
		ssid = resolvedSSID
		if *verbose {
			fmt.Printf("Resolved SSID: %s\n", ssid)
		}
	}

	if *targetChannel == 0 {
		// If user didn't specify target channel try to resole it from cache
		if net, err := getCachedNetwork(*targetDevice); err == nil {
			*targetChannel = net.Channel
		} else {
			fmt.Println("Warning: Can not load target network channel from cache. Using default.")
			*targetChannel = 11
		}
	}

	fmt.Printf("Starting packet capture. Iface: %s Channel: %d, Target router: %s (SSID: %s)\n", *targetInterface, *targetChannel, *targetDevice, ssid)

	// On newer mac it is required to dissociate from active WiFi network before using monitor mode
	err := dissociateWiFi()
	if err != nil {
		log.Fatal(err)
	}

	devices, err := monitor(db, *targetInterface, *targetDevice, *targetChannel, *maxNumPackets)
	if err != nil {
		log.Fatal(err)
	}

	ratedDevices, err := rateConnections(db, *targetInterface, *targetDevice, ssid, devices)
	if err != nil {
		log.Fatal(err)
	}

	bestDevice := getBestDevice(ratedDevices)

	if bestDevice.Rating == 0 {
		fmt.Println("None of the devices has internet access. Exiting!")

		if err := resetOriginalMac(db, *targetInterface, *verbose); err != nil {
			fmt.Println("Can not restore original mac", err)
		}

		return
	}

	fmt.Printf("Setting mac to %s with connection rating %d\n", bestDevice.Address, bestDevice.Rating)
	setMac(*targetInterface, bestDevice.Address)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			log.Println("Terminated by user")
			os.Exit(0)
		}
	}()
}

// cmdScan scans for available WiFi networks
func cmdScan() {
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	scan5G := scanCmd.Bool("5g", false, "also scan 5GHz channels (slower)")
	scanTime := scanCmd.Int("t", 200, "time in milliseconds to monitor each channel")
	sortBy := scanCmd.String("s", "signal", "sort results by: signal or security")
	targetInterface := scanCmd.String("i", "en0", "name of wifi interface")
	verbose := scanCmd.Bool("v", false, "output more information")

	scanCmd.Parse(os.Args[2:])

	if *verbose {
		fmt.Printf("Scanning for networks on interface %s\n", *targetInterface)
	}

	// Dissociate from current network to enable monitor mode
	if err := dissociateWiFi(); err != nil {
		fmt.Printf("Warning: failed to dissociate from WiFi: %v\n", err)
	}

	channels := defaultChannels2G
	if *scan5G {
		channels = append(channels, defaultChannels5G...)
	}

	aps, err := scanForAccessPoints(*targetInterface, channels, time.Duration(*scanTime)*time.Millisecond, *verbose)
	if err != nil {
		fmt.Printf("Error scanning for access points: %v\n", err)
		return
	}

	// Populate network cache
	if err := populateNetworkCache(aps, *verbose); err != nil {
		fmt.Printf("Warning: failed to populate network cache: %v\n", err)
	}

	printAccessPoints(aps, *sortBy)
}

// cmdCapture runs packet capture only
func cmdCapture(db *scribble.Driver) {
	captureCmd := flag.NewFlagSet("capture", flag.ExitOnError)
	targetInterface := captureCmd.String("i", "en0", "name of wifi interface")
	targetDevice := captureCmd.String("t", defaultTarget, "MAC address of target wifi network")
	targetChannel := captureCmd.Int("ch", 11, "target radio channel (1-14)")
	maxNumPackets := captureCmd.Int("n", 300, "number of packets to capture")
	verbose := captureCmd.Bool("v", false, "output more information")

	captureCmd.Parse(os.Args[2:])

	interfaceStore := fmt.Sprintf("store/interfaces/%s.json", *targetInterface)

	if _, err := os.Stat(interfaceStore); os.IsNotExist(err) {
		currentMacAddress, err := getMac(*targetInterface)
		if err != nil {
			log.Fatal(err)
		}

		if *verbose {
			fmt.Printf("Saving current mac address %s to %s\n", currentMacAddress, interfaceStore)
		}

		currentInterface := networkInterface{
			Name:    *targetInterface,
			Address: currentMacAddress,
		}

		db.Write("interfaces", *targetInterface, currentInterface)
	}

	if *verbose {
		fmt.Printf("Starting packet capture. Iface: %s Channel: %d, Target router: %s\n", *targetInterface, *targetChannel, *targetDevice)
	}

	// On newer mac it is required to dissociate from active WiFi network before using monitor mode
	err := dissociateWiFi()
	if err != nil {
		log.Fatal(err)
	}

	_, err = monitor(db, *targetInterface, *targetDevice, *targetChannel, *maxNumPackets)
	if err != nil {
		log.Fatal(err)
	}
}

// cmdJoin connects to a WiFi network
func cmdJoin() {
	joinCmd := flag.NewFlagSet("join", flag.ExitOnError)
	password := joinCmd.String("p", "", "password for WiFi network")
	verbose := joinCmd.Bool("v", false, "output more information")

	joinCmd.Parse(os.Args[2:])

	args := joinCmd.Args()
	if len(args) < 1 {
		fmt.Println("Usage: anticap join -p <password> <SSID>")
		os.Exit(1)
	}

	ssid := args[0]

	if *verbose {
		fmt.Printf("Connecting to network: %s\n", ssid)
	}

	_, err := associateWiFi(ssid, *password)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}

	if *verbose {
		fmt.Printf("Successfully connected to %s\n", ssid)
	}
}

// cmdReset resets to original MAC address
func cmdReset(db *scribble.Driver) {
	resetCmd := flag.NewFlagSet("reset", flag.ExitOnError)
	targetInterface := resetCmd.String("i", "en0", "name of wifi interface")
	verbose := resetCmd.Bool("v", false, "output more information")

	resetCmd.Parse(os.Args[2:])

	if *verbose {
		fmt.Printf("Resetting MAC address for interface %s\n", *targetInterface)
	}

	if err := resetOriginalMac(db, *targetInterface, *verbose); err != nil {
		fmt.Println("Can not restore original mac", err)
	}
}

// cmdSetMac sets the interface MAC address
func cmdSetMac() {
	setMacCmd := flag.NewFlagSet("setmac", flag.ExitOnError)
	targetInterface := setMacCmd.String("i", "en0", "name of wifi interface")
	verbose := setMacCmd.Bool("v", false, "output more information")

	setMacCmd.Parse(os.Args[2:])

	args := setMacCmd.Args()
	if len(args) < 1 {
		fmt.Println("Usage: anticap setmac -i <interface> <MAC_ADDRESS>")
		os.Exit(1)
	}

	macAddress := args[0]

	if *verbose {
		fmt.Printf("Setting MAC address of %s to %s\n", *targetInterface, macAddress)
	}

	setMac(*targetInterface, macAddress)
}

// cmdList lists stored captures for target MAC
func cmdList(db *scribble.Driver) {
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	targetDevice := listCmd.String("t", defaultTarget, "MAC address of target wifi network")
	verbose := listCmd.Bool("v", false, "output more information")

	listCmd.Parse(os.Args[2:])

	if *verbose {
		fmt.Printf("Listing captures for target: %s\n", *targetDevice)
	}

	records, err := db.ReadAll(*targetDevice)
	if err != nil {
		fmt.Println("Error reading database.", err)
		return
	}

	devices := make(map[string]device)

	for _, d := range records {
		device := device{}
		if err := json.Unmarshal([]byte(d), &device); err != nil {
			fmt.Println("Error unmarshalling db entry.", err)
		}

		devices[device.Address] = device
	}

	for _, d := range sortDevices(devices) {
		fmt.Printf("%s %d\n", d.Address, d.PCount)
	}
}

// resolveSSIDFromBSSID attempts to resolve SSID from BSSID using cache-first approach
func resolveSSIDFromBSSID(bssid, iface string, verbose bool) (string, error) {
	// First, try cache lookup
	if net, err := getCachedNetwork(bssid); err == nil {
		if verbose {
			fmt.Printf("Found SSID in cache: %s -> %s\n", bssid, net.SSID)
		}
		return net.SSID, nil
	}

	// Cache miss, try full scan
	fmt.Printf("SSID not in cache, performing scan for %s\n", bssid)

	// Dissociate from current network to enable monitor mode
	if err := dissociateWiFi(); err != nil {
		if verbose {
			fmt.Printf("Warning: failed to dissociate from WiFi: %v\n", err)
		}
	}

	channels := append(defaultChannels2G, defaultChannels5G...)
	scanTime := 300 * time.Millisecond

	aps, err := scanForAccessPoints(iface, channels, scanTime, verbose)
	if err != nil {
		return "", fmt.Errorf("scan failed: %w", err)
	}

	// Update cache with scan results
	if err := populateNetworkCache(aps, verbose); err != nil {
		if verbose {
			fmt.Printf("Warning: failed to populate cache: %v\n", err)
		}
	}

	// Try cache lookup again
	if net, err := getCachedNetwork(bssid); err == nil {
		return net.SSID, nil
	}

	return "", fmt.Errorf("BSSID %s not found in scan results", bssid)
}

// getCachedNetwork retrieves SSID for given BSSID from cache
func getCachedNetwork(bssid string) (CachedNetwork, error) {
	cacheFile := filepath.Join("store", "networks", bssid+".json")

	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return CachedNetwork{}, fmt.Errorf("no cache entry for BSSID %s", bssid)
	}

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return CachedNetwork{}, fmt.Errorf("failed to read cache file: %w", err)
	}

	var info CachedNetwork
	if err := json.Unmarshal(data, &info); err != nil {
		return CachedNetwork{}, fmt.Errorf("failed to parse cache file: %w", err)
	}

	return info, nil
}

// populateNetworkCache stores discovered networks in individual cache files
func populateNetworkCache(aps map[string]AccessPoint, verbose bool) error {
	cacheDir := filepath.Join("store", "networks")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	count := 0
	for bssid, ap := range aps {
		// Skip networks without SSID
		if ap.SSID == "" {
			continue
		}

		info := CachedNetwork{
			BSSID:   bssid,
			SSID:    ap.SSID,
			Channel: ap.Channel,
		}

		data, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			if verbose {
				fmt.Printf("Warning: failed to marshal network info for %s: %v\n", bssid, err)
			}
			continue
		}

		cacheFile := filepath.Join(cacheDir, bssid+".json")
		if err := os.WriteFile(cacheFile, data, 0644); err != nil {
			if verbose {
				fmt.Printf("Warning: failed to write cache file for %s: %v\n", bssid, err)
			}
			continue
		}
		count++
	}

	if verbose {
		fmt.Printf("Cached %d networks in %s\n", count, cacheDir)
	}

	return nil
}
