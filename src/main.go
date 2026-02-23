package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// APUpdateMsg is a message sent when an access point is updated
type APUpdateMsg struct {
	BSSID      string
	SSID       string
	Security   Dot11Security
	Channel    int
	Signal     int
	NumPackets int
}

// ChannelUpdateMsg is sent when starting to scan a new channel
type ChannelUpdateMsg struct {
	Channel int
}

// HandshakeUpdateMsg is sent when a handshake frame is captured
type HandshakeUpdateMsg struct {
	BSSID string
	Frame HandshakeFrame
}

type ClientUpdateMsg struct {
	BSSID     string
	ClientMAC string
}

var defaultChannels2G = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
var defaultChannels5G = []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan()
	case "guess":
		cmdGuess()
	case "join":
		cmdJoin()
	case "setmac":
		cmdSetMac()
	case "setchan":
		cmdSetChannel()
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`anticap - Captive portal bypass and WiFi network analysis tool

Usage:
  anticap <command> [options]

Commands:
  scan       Scan for available WiFi networks
  join       Connect to a WiFi network by name
  setmac     Set interface MAC address
  setchan    Set interface radio channel

Use "anticap <command> -h" for more information about a command.`)
}

func strToIntSlice(str string) []int {
	parts := strings.Split(str, ",")
	chans := []int{}
	for _, c := range parts {
		ch, err := strconv.ParseInt(c, 10, 32)
		if err != nil {
			fmt.Printf("can not parse string to int slice %s\n", c)
			continue
		}
		chans = append(chans, int(ch))
	}
	return chans
}

/*
 *	COMMANDS
 */

// Scans for available WiFi networks
func cmdScan() {
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	scanBands := scanCmd.String("b", "2g", "comma separated list of bands to scan (e.g. 2g,5g)")
	scanChan := scanCmd.String("ch", "", "scan specified channels. This will override band selector (-b) (e.g. 6,11)")
	// By default AP transmit every 100ms
	scanTime := scanCmd.Int("t", 250, "time in milliseconds to monitor each channel")
	sortBy := scanCmd.String("s", "signal", "sort results by: signal or security")
	targetInterface := scanCmd.String("i", "en0", "name of wifi interface")
	outputPcapFile := scanCmd.String("o", "", "output pcap file")
	verbose := scanCmd.Bool("v", false, "output more information")

	scanCmd.Parse(os.Args[2:])

	if !isSudo() {
		fmt.Println("This command must be run as root")
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("Scanning for networks on interface %s\n", *targetInterface)
	}

	// Dissociate from current network to enable monitor mode
	if err := dissociateWiFi(); err != nil {
		fmt.Printf("Warning: failed to dissociate from WiFi: %v\n", err)
	}

	bands := strings.Split(*scanBands, ",")

	channels := []int{}
	for _, b := range bands {
		if b == "2g" {
			channels = append(channels, defaultChannels2G...)
		}
		if b == "5g" {
			channels = append(channels, defaultChannels5G...)
		}
	}

	if *scanChan != "" {
		channels = strToIntSlice(*scanChan)
	}

	// Channel for updates
	apUpdateCh := make(chan APUpdateMsg, 100)
	clientUpdateCh := make(chan ClientUpdateMsg, 100)
	channelUpdateCh := make(chan ChannelUpdateMsg, 10)
	handshakeUpdateCh := make(chan HandshakeUpdateMsg, 100)
	errUpdateCh := make(chan error, 10)

	// Run scan in goroutine
	go func() {
		defer close(apUpdateCh)
		err := scan(
			*targetInterface,
			channels,
			time.Duration(*scanTime)*time.Millisecond,
			*outputPcapFile,
			apUpdateCh,
			clientUpdateCh,
			channelUpdateCh,
			handshakeUpdateCh,
			errUpdateCh)
		if err != nil {
			fmt.Printf("Error scanning for access points: %v\n", err)
			return
		}
	}()

	// Create Bubble Tea model
	m := NewScanModel()
	m.SortBy = *sortBy
	m.Scanning = true

	// Create Bubble Tea program
	p := tea.NewProgram(m)

	// Handle UI updates
	go func() {
		for {
			select {
			case msg, ok := <-apUpdateCh:
				if !ok {
					p.Send(ScanCompleteMsg{})
					return
				}
				p.Send(msg)
			case msg := <-clientUpdateCh:
				p.Send(msg)
			case chMsg := <-channelUpdateCh:
				p.Send(chMsg)
			case hsMsg := <-handshakeUpdateCh:
				p.Send(hsMsg)
			case err := <-errUpdateCh:
				p.Send(err)
			}
		}
	}()

	// Start the UI
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v\n", err)
		os.Exit(1)
	}
}

// Connects to a WiFi network by name
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

	if !isSudo() {
		fmt.Println("This command must be run as root")
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

func cmdGuess() {
	// TODO
}

// Sets the interface MAC address
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

	if !isSudo() {
		fmt.Println("This command must be run as root")
		os.Exit(1)
	}

	macAddress := args[0]

	if *verbose {
		fmt.Printf("Setting MAC address of %s to %s\n", *targetInterface, macAddress)
	}

	setMac(*targetInterface, macAddress)
}

// Set target interface channel
// Note that this will leave the interface in dissociated state
func cmdSetChannel() {
	setChannelCmd := flag.NewFlagSet("setchannel", flag.ExitOnError)
	iface := setChannelCmd.String("i", "en0", "name of wifi interface")
	verbose := setChannelCmd.Bool("v", false, "output more information")

	setChannelCmd.Parse(os.Args[2:])

	args := setChannelCmd.Args()
	if len(args) < 1 {
		fmt.Println("Usage: anticap setchannel -i <interface> <CHANNEL>")
		os.Exit(1)
	}

	if !isSudo() {
		fmt.Println("This command must be run as root")
		os.Exit(1)
	}

	channel, err := strconv.ParseInt(args[0], 10, 32)
	if err != nil {
		fmt.Println("can not parse channel:", err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("Setting channel of %s to %d\n", *iface, channel)
	}

	if err := setChannel(*iface, int(channel)); err != nil {
		fmt.Println("Error setting channel:", err)
		os.Exit(1)
	}
}
