package main

import (
	"fmt"
	"time"

	ping "github.com/sparrc/go-ping"
)

func rateConnection(pingCount int) (int, error) {
	pinger, err := ping.NewPinger("www.google.com")
	if err != nil {
		return 0, err
	}

	pinger.Timeout = 4000

	pinger.Count = pingCount
	pinger.Run() // blocks until finished
	stats := pinger.Statistics()

	return stats.PacketsSent, nil
}

func rateConnections(intrfc string, devices map[string]int) (map[string]int, error) {
	rated := make(map[string]int)

	for address := range devices {
		if *debug {
			fmt.Println("Setting mac to ", address)
		}

		if err := setMac(intrfc, address); err != nil {
			return nil, err
		}

		time.Sleep(10 * time.Second)

		if *debug {
			fmt.Println("Testing connection for", address)
		}
		connectionScore, err := rateConnection(10)
		if err != nil {
			fmt.Println(err)
			connectionScore = 0
		}
		if *debug {
			fmt.Println("Score ", connectionScore)
		}

		rated[address] = connectionScore

		// if connectionScore > bestScore {
		// 	selectedAddress = address
		// 	bestScore = connectionScore
		// }
	}
	return rated, nil
}
