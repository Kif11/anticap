package main

import (
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
var debug = flag.Bool("v", false, "verbose output")
var captureOnly = flag.Bool("s", false, "run packet capture and exit")
var resetOriginal = flag.Bool("r", false, "reset to original mac address and exit")
var targetInterface = flag.String("i", "en0", "name of wifi interface, use ifconfig to find out")
var targetDevice = flag.String("t", defaultTarget, "mac address of target wifi network")
var maxNumPackets = flag.Int("n", 100, "number of packets to capture before stop")

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
		i := networkInterface{}
		if err := db.Read("interfaces", *targetInterface, &i); err != nil {
			panic(err)
		}
		if *debug {
			fmt.Printf("Resseting mac address to %s for %s\n", i.Address, *targetInterface)
		}
		setMac(*targetInterface, i.Address)
		return
	}

	interfaceStore := fmt.Sprintf("store/interfaces/%s.json", *targetInterface)

	if _, err := os.Stat(interfaceStore); os.IsNotExist(err) {
		currentMacAddress, err := getMac(*targetInterface)
		if err != nil {
			panic(err)
		}

		if *debug {
			fmt.Printf("Saving current mac address %s to %s\n", currentMacAddress, interfaceStore)
		}

		currentInterface := networkInterface{
			Name:    *targetInterface,
			Address: currentMacAddress,
		}

		db.Write("interfaces", *targetInterface, currentInterface)
	}

	// records, err := db.ReadAll("fc:ec:da:36:93:d4")
	// if err != nil {
	// 	fmt.Println("Error", err)
	// }

	// fmt.Println(records)

	if *debug {
		fmt.Printf("Starting packet capture on %s for %s hotspot\n", *targetInterface, *targetDevice)
	}

	devices, err := monitor(db, *targetInterface, *targetDevice, *maxNumPackets)
	if err != nil {
		panic(err)
	}

	if *captureOnly {
		return
	}

	ratedDevices, err := rateConnections(db, *targetInterface, *targetDevice, devices)
	if err != nil {
		panic(err)
	}

	bestDevice := getBestDevice(ratedDevices)

	if bestDevice.Rating == 0 {
		if *debug {
			fmt.Println("Non of the devices has internet access. Exiting!")
		}
		return
	}

	if *debug {
		fmt.Printf("Setting mac to %s with connection rating %d\n", bestDevice.Address, bestDevice.Rating)
	}
	setMac(*targetInterface, bestDevice.Address)

	return
}
