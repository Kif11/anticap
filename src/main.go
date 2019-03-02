package main

import (
	"flag"
	"fmt"
)

var debug = flag.Bool("v", false, "verbose output")

func main() {
	store := store{}
	store.initDB()

	defaultTarget, err := getRouterAddress()
	if err != nil {
		fmt.Printf("can not determine target device mac address automatically please set it with -t option")
	}

	targetInterface := flag.String("i", "en0", "name of wifi interface, use ifconfig to find out")
	targetDevice := flag.String("t", defaultTarget, "only packets originated from this router will be captures")
	// printAddresses := flag.Bool("a", false, "output destination and source addresses")
	maxNumPackets := 10

	flag.Parse()

	store.insert(
		"interfaces",
		[]string{"interface", "address"},
		[]string{*targetInterface, *targetDevice},
	)

	if *debug {
		fmt.Printf("Starting packet capture on %s for %s hotspot\n", *targetInterface, *targetDevice)
	}

	devices, err := monitor("en0", *targetDevice, maxNumPackets)
	if err != nil {
		panic(err)
	}

	for address, numPackets := range devices {
		store.insert(
			"devices",
			[]string{"address", "router_address", "num_packets"},
			[]string{address, *targetDevice, fmt.Sprintf("%d", numPackets)},
		)
	}

	// devicesFromDb := store.getDevices()
	// fmt.Println(devicesFromDb)

	// selectedAddress := ""
	// bestScore := 0

	rated, err := rateConnections(*targetInterface, devices)
	if err != nil {
		panic(err)
	}

	fmt.Println(rated)

	// stmt, err := tx.Prepare(fmt.Sprintf(`UPDATE "devices"
	// 	 SET score = (?)
	// 	 WHERE address = %s;
	// 	`, connectionScore, address))
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer stmt.Close()

	// _, err = stmt.Exec(connectionScore)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// tx.Commit()

	// fmt.Println("Selected mac", selectedAddress, " with score ", bestScore)
}
