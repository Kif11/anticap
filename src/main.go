package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

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

var defaultTarget, err = getRouterAddress()
var spoofMac = flag.String("s", "", "set target interface mac to this one and exit")
var resetOriginal = flag.Bool("r", false, "reset to original mac address and exit")
var quite = flag.Bool("q", false, "do not print logs")
var captureOnly = flag.Bool("c", false, "run packet capture and exit")
var listCaptures = flag.Bool("l", false, "list stored captures for target mac")
var targetInterface = flag.String("i", "en0", "name of wifi interface, use ifconfig to find out")
var targetDevice = flag.String("t", defaultTarget, "mac address of target wifi network")
var maxNumPackets = flag.Int("n", 300, "number of packets to capture before stop")

func main() {
	flag.Parse()

	if !isSudo() {
		fmt.Println("This program must be run as root")
		return
	}

	if err != nil {
		fmt.Printf("can not determine target device mac address automatically please set it with -t option")
	}

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

		if !*quite {
			fmt.Printf("Saving current mac address %s to %s\n", currentMacAddress, interfaceStore)
		}

		currentInterface := networkInterface{
			Name:    *targetInterface,
			Address: currentMacAddress,
		}

		db.Write("interfaces", *targetInterface, currentInterface)
	}

	if !*quite {
		fmt.Printf("Starting packet capture on %s for %s hotspot\n", *targetInterface, *targetDevice)
	}

	devices, err := monitor(db, *targetInterface, *targetDevice, *maxNumPackets)
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
		if !*quite {
			fmt.Println("Non of the devices has internet access. Exiting!")
		}

		if err := resetOriginalMac(db, *targetInterface); err != nil {
			fmt.Println("Can not restore original mac", err)
		}

		return
	}

	if !*quite {
		fmt.Printf("Setting mac to %s with connection rating %d\n", bestDevice.Address, bestDevice.Rating)
	}
	setMac(*targetInterface, bestDevice.Address)

	return
}
