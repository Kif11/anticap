package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	scribble "github.com/nanobox-io/golang-scribble"
)

type device struct {
	Address string
	PCount  int
	Rating  int
}

type networkInterface struct {
	Name    string
	Address string
}

// Common 2.4GHz and 5GHz channels
var defaultChannels2G = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
var defaultChannels5G = []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}

var defaultTarget, err = getRouterAddress()
var spoofMac = flag.String("s", "", "set target interface mac to this one and exit")
var resetOriginal = flag.Bool("r", false, "reset to original mac address and exit")
var verbose = flag.Bool("v", false, "output more information")
var captureOnly = flag.Bool("c", false, "run packet capture and exit")
var listCaptures = flag.Bool("l", false, "list stored captures for target mac")
var scanNetworks = flag.Bool("scan", false, "scan for wifi networks using monitor mode to get actual BSSIDs (disconnects from WiFi)")
var scanDwell = flag.Int("dwell", 200, "time in milliseconds to dwell on each channel during scan")
var scan5G = flag.Bool("5g", false, "also scan 5GHz channels during network scan (slower)")
var sortBySecurity = flag.Bool("weak", false, "sort scan results by security (weakest first) instead of signal strength")
var joinNetwork = flag.String("join", "", "connect to WiFi network by SSID")
var wifiPassword = flag.String("pass", "", "password for WiFi network (use with -join)")
var targetInterface = flag.String("i", "en0", "name of wifi interface, use ifconfig to find out")
var targetChannel = flag.Int("ch", 11, "target radio channels (1-14). use sudo airport -s to determine active channel")
var targetDevice = flag.String("t", defaultTarget, "mac address of target wifi network")
var maxNumPackets = flag.Int("n", 300, "number of packets to capture before stop")

func main() {
	flag.Parse()

	if !isSudo() {
		fmt.Println("This program must be run as root")
		return
	}

	// if err != nil {
	// 	fmt.Printf("can not determine target device mac address automatically please set it with -t option")
	// }

	dir := "./store"

	db, err := scribble.New(dir, nil)
	if err != nil {
		fmt.Println("Error", err)
	}

	if *resetOriginal {
		if err := resetOriginalMac(db, *targetInterface); err != nil {
			fmt.Println("Can not restore original mac", err)
		}
		return
	} else if *listCaptures {
		records, err := db.ReadAll(*targetDevice)
		if err != nil {
			fmt.Println("Error reading database.", err)
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

		return

	} else if *scanNetworks {
		// Use monitor mode to scan for beacons and get available wifi networks with BSSIDs

		// Dissociate from current network to enable monitor mode
		if err := dissociateWiFi(); err != nil {
			fmt.Printf("Warning: failed to dissociate from WiFi: %v\n", err)
		}

		channels := defaultChannels2G
		if *scan5G {
			channels = append(channels, defaultChannels5G...)
		}

		dwellTime := time.Duration(*scanDwell) * time.Millisecond

		aps, err := ScanForAccessPoints(*targetInterface, channels, dwellTime)
		if err != nil {
			fmt.Printf("Error scanning for access points: %v\n", err)
			return
		}

		PrintAccessPoints(aps, *sortBySecurity)
		return

	} else if *joinNetwork != "" {
		_, err := associateWiFi(*joinNetwork, *wifiPassword)
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			return
		}

		return
	} else if *spoofMac != "" {
		setMac(*targetInterface, *spoofMac)
		return
	}

	interfaceStore := fmt.Sprintf("store/interfaces/%s.json", *targetInterface)

	if _, err := os.Stat(interfaceStore); os.IsNotExist(err) {
		currentMacAddress, err := getMac(*targetInterface)
		if err != nil {
			panic(err)
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
	err = dissociateWiFi()
	if err != nil {
		panic(err)
	}

	devices, err := monitor(db, *targetInterface, *targetDevice, *targetChannel, *maxNumPackets)
	if err != nil {
		panic(err)
	}

	// sortedDevices := sortDevices(devices)
	// fmt.Println("Sorted devices", sortedDevices)

	if *captureOnly {
		return
	}

	ratedDevices, err := rateConnections(db, *targetInterface, *targetDevice, devices)
	if err != nil {
		panic(err)
	}

	bestDevice := getBestDevice(ratedDevices)

	if bestDevice.Rating == 0 {
		if *verbose {
			fmt.Println("Non of the devices has internet access. Exiting!")
		}

		if err := resetOriginalMac(db, *targetInterface); err != nil {
			fmt.Println("Can not restore original mac", err)
		}

		return
	}

	if *verbose {
		fmt.Printf("Setting mac to %s with connection rating %d\n", bestDevice.Address, bestDevice.Rating)
	}
	setMac(*targetInterface, bestDevice.Address)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			// sig is a ^C, handle it
			log.Println("Terminated by user")
			os.Exit(0)
		}
	}()
}
